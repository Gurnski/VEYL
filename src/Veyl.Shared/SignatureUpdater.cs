using System.Text.RegularExpressions;

namespace Veyl.Shared;

/// <summary>
/// Merges small hash lists into the shared signature file (hashes.txt). A feed is any
/// URL or local file serving lines that start with an MD5, SHA-1 or SHA-256 in hex
/// (anything after the hash on the same line is used as the detection name).
/// Big lists such as VirusShare go into a signature pack instead (<see cref="Scanner.CompilePack"/>):
/// this class reads the whole text file on every merge.
/// </summary>
public static partial class SignatureUpdater
{
    [GeneratedRegex("^([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?:[\\s,;]+(.*))?$")]
    private static partial Regex HashLine();

    /// <summary>VirusShare's lists are named VirusShare_00000.md5 and so on.</summary>
    public static string PackLabelFor(IEnumerable<string> files) =>
        files.All(f => Path.GetFileName(f).StartsWith("VirusShare", StringComparison.OrdinalIgnoreCase)) ? "VirusShare" : "Imported";

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };

    public static Dictionary<string, string> Parse(IEnumerable<string> lines, string defaultName)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string raw in lines)
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var m = HashLine().Match(line);
            if (!m.Success) continue;
            string name = m.Groups[2].Value.Trim().Trim('"');
            map[m.Groups[1].Value.ToLowerInvariant()] = name.Length > 0 ? name : defaultName;
        }
        return map;
    }

    /// <summary>Adds new hashes to the signature file. Returns how many were new.</summary>
    public static int Merge(IReadOnlyDictionary<string, string> incoming)
    {
        var existing = File.Exists(VeylPaths.SignatureFile)
            ? Parse(File.ReadLines(VeylPaths.SignatureFile), "Blocklisted file")
            : [];
        var added = incoming.Where(kv => !existing.ContainsKey(kv.Key)).ToList();
        if (added.Count == 0) return 0;

        using var w = File.AppendText(VeylPaths.SignatureFile);
        w.WriteLine($"# merged {DateTime.Now:yyyy-MM-dd HH:mm}");
        foreach (var (hash, name) in added) w.WriteLine($"{hash} {name}");
        return added.Count;
    }

    public static async Task<int> UpdateFromFeedsAsync(IEnumerable<string> feeds, CancellationToken token = default)
    {
        int total = 0;
        foreach (string feed in feeds.Where(f => !string.IsNullOrWhiteSpace(f)))
        {
            try
            {
                string text = Uri.TryCreate(feed, UriKind.Absolute, out var uri) && uri.Scheme.StartsWith("http")
                    ? await Http.GetStringAsync(uri, token)
                    : await File.ReadAllTextAsync(feed, token);
                string host = uri?.Host ?? Path.GetFileName(feed);
                total += Merge(Parse(text.Split('\n'), $"Feed:{host}"));
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException)
            {
                // One bad feed should not stop the others.
            }
        }
        return total;
    }
}
