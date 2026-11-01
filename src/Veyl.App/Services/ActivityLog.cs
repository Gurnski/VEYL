using System.Collections.ObjectModel;
using System.Text.Json;
using System.Text.Json.Serialization;
using Veyl.Shared;

namespace Veyl.App.Services;

public enum LogKind { System, Scan, Threat, Quarantine, Vault, Realtime }

public sealed record ActivityItem(DateTimeOffset Time, LogKind Kind, string Title, string Detail)
{
    [JsonIgnore]
    public string Glyph => Kind switch
    {
        LogKind.Scan => "",
        LogKind.Threat => "",
        LogKind.Quarantine => "",
        LogKind.Vault => "",
        LogKind.Realtime => "",
        _ => "",
    };

    [JsonIgnore]
    public string When => Ui.Ago(Time);
}

/// <summary>Per-user event history, appended to activity.jsonl in the user's data folder.</summary>
public sealed class ActivityLog
{
    private const int Keep = 500;
    private static readonly JsonSerializerOptions Compact = new(Manifest.Json) { WriteIndented = false };
    private readonly object _fileLock = new();

    public ObservableCollection<ActivityItem> Items { get; } = [];

    public void Load()
    {
        if (!File.Exists(VeylPaths.ActivityFile)) return;
        var lines = File.ReadAllLines(VeylPaths.ActivityFile);
        foreach (string line in lines.Reverse().Take(Keep))
        {
            try
            {
                if (JsonSerializer.Deserialize<ActivityItem>(line, Compact) is { } item) Items.Add(item);
            }
            catch (JsonException) { }
        }
        // Keep the file from growing forever.
        if (lines.Length > Keep * 2) File.WriteAllLines(VeylPaths.ActivityFile, lines[^Keep..]);
    }

    public void Add(LogKind kind, string title, string detail = "")
    {
        var item = new ActivityItem(DateTimeOffset.Now, kind, title, detail);
        lock (_fileLock)
        {
            try { File.AppendAllText(VeylPaths.ActivityFile, JsonSerializer.Serialize(item, Compact) + "\n"); }
            catch (IOException) { }
        }
        Ui.Post(() =>
        {
            Items.Insert(0, item);
            if (Items.Count > Keep) Items.RemoveAt(Items.Count - 1);
        });
    }
}
