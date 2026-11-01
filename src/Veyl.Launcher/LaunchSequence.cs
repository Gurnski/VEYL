using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using Veyl.Shared;

namespace Veyl.Launcher;

public sealed record LaunchStep(string Title, string Detail, double Progress);

public sealed record LaunchResult(bool Ok, string Title, string Detail, string? UpdateVersion = null);

/// <summary>Startup checks: install integrity, data folders, update check, signature feeds.</summary>
public sealed class LaunchSequence
{
    public const string AppExe = "Veyl.App.exe";
    private static readonly HttpClient Http = Web.Client(TimeSpan.FromSeconds(5));

    public async Task<LaunchResult> RunAsync(Action<LaunchStep> report)
    {
        string dir = VeylPaths.InstallDir;
        Manifest? manifest;

        // 1. Integrity
        report(new("Checking installation", "Verifying VEYL's files haven't been changed.", 0.1));
        try
        {
            manifest = Manifest.Load(dir);
        }
        catch (Exception ex)
        {
            return new(false, "Installation is damaged", $"manifest.json could not be read: {ex.Message}");
        }
        if (!File.Exists(Path.Combine(dir, AppExe)))
            return new(false, "VEYL is not installed correctly", $"{AppExe} is missing from {dir}.");

        if (manifest is not null)
        {
            string? bad = await Task.Run(() => FirstTamperedFile(dir, manifest));
            if (bad is not null)
                return new(false, "Integrity check failed",
                    $"{bad} doesn't match the release it shipped with. Reinstall VEYL before running it.");
        }
        await Pace();

        // 2. Data folders
        report(new("Preparing your data", $"Signed in as {VeylPaths.UserName}.", 0.3));
        try
        {
            await Task.Run(VeylPaths.EnsureCreated);
        }
        catch (Exception ex)
        {
            return new(false, "Couldn't prepare data folders", ex.Message);
        }
        await Pace();

        // 3. Updates
        report(new("Checking for updates", "Looking for a newer release.", 0.5));
        string? update = null;
        if (manifest is { UpdateUrl.Length: > 0 })
        {
            try
            {
                var remote = Manifest.Parse(await Http.GetStringAsync(manifest.UpdateUrl));
                if (remote is not null && Manifest.IsNewer(remote.Version, manifest.Version)) update = remote.Version;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
            {
                // Offline or the update server is down; carry on with the installed version.
            }
        }
        await Pace();

        // 4. Signatures
        var settings = UserSettings.Load();
        var feeds = (manifest?.SignatureFeeds ?? []).Concat(settings.SignatureFeeds).Distinct().ToList();
        bool due = settings.LastSignatureUpdate is null || DateTimeOffset.Now - settings.LastSignatureUpdate > TimeSpan.FromHours(12);
        if (feeds.Count > 0 && due)
        {
            report(new("Updating signatures", $"Fetching {feeds.Count} feed(s).", 0.7));
            try
            {
                await SignatureUpdater.UpdateFromFeedsAsync(feeds).WaitAsync(TimeSpan.FromSeconds(15));
                settings.LastSignatureUpdate = DateTimeOffset.Now;
                settings.Save();
            }
            // Feeds are optional: no failure here (timeout, no write access, bad file) may block the launch.
            catch (Exception) { /* the app can retry from the Signatures page */ }
        }
        else
        {
            report(new("Loading signatures", "Signature database is current.", 0.7));
            await Pace();
        }

        report(new("Starting VEYL", update is null ? "Up to date." : $"Version {update} is available.", 0.9));
        return new(true, "Ready", "", update);
    }

    private static Task Pace() => App.Autostart ? Task.CompletedTask : Task.Delay(350);

    private static string? FirstTamperedFile(string dir, Manifest manifest)
    {
        foreach (var (name, expected) in manifest.Files)
        {
            string path = Path.Combine(dir, name);
            if (!File.Exists(path)) return name;
            try
            {
                using var fs = File.OpenRead(path);
                string actual = Convert.ToHexString(SHA256.HashData(fs));
                if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase)) return name;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return name;  // unreadable counts as failed, never as passed
            }
        }
        return null;
    }

    /// <summary>Starts the main app and waits briefly for it to report ready.</summary>
    public static bool StartApp(bool tray, string? updateVersion)
    {
        using var ready = InstanceNames.CreateEvent(InstanceNames.ReadyEvent, EventResetMode.ManualReset);
        var args = new List<string>();
        if (tray) args.Add("--tray");
        if (updateVersion is not null) args.Add($"--update={updateVersion}");

        var psi = new ProcessStartInfo(Path.Combine(VeylPaths.InstallDir, AppExe), args)
        {
            UseShellExecute = false,
            WorkingDirectory = VeylPaths.InstallDir,
        };
        using var p = Process.Start(psi);
        return p is not null && ready.WaitOne(TimeSpan.FromSeconds(15));
    }
}
