using System.Collections.ObjectModel;
using System.Diagnostics;
using Veyl.Shared;

namespace Veyl.App.Services;

public enum ScanKind { Quick, Full, Custom }

public sealed class Detection : Observable
{
    public required ScanResult Result { get; init; }
    public string FileName => Path.GetFileName(Result.Path);
    public string Folder => Path.GetDirectoryName(Result.Path) ?? "";
    public bool IsMalicious => Result.Verdict == Verdict.Malicious;
    public string Severity => IsMalicious ? "MALICIOUS" : $"SUSPICIOUS · {Result.Score}";

    private string _state = "";
    /// <summary>"" while pending, otherwise what happened to it (e.g. "Quarantined").</summary>
    public string State { get => _state; set { if (Set(ref _state, value)) Raise(nameof(IsResolved)); } }
    public bool IsResolved => _state.Length > 0;
}

/// <summary>Runs on-demand scans on a background thread and exposes progress for the UI.</summary>
public sealed class ScanService : Observable
{
    private CancellationTokenSource? _cts;
    private readonly Stopwatch _clock = new();

    public ObservableCollection<Detection> Detections { get; } = [];

    private bool _running;
    public bool IsRunning { get => _running; private set => Set(ref _running, value); }

    private ScanKind _kind;
    public ScanKind Kind { get => _kind; private set => Set(ref _kind, value); }

    private string _current = "";
    public string CurrentPath { get => _current; private set => Set(ref _current, value); }

    private int _files;
    public int FilesScanned { get => _files; private set => Set(ref _files, value); }

    private string _elapsed = "";
    public string Elapsed { get => _elapsed; private set => Set(ref _elapsed, value); }

    private string _summary = "";
    public string Summary { get => _summary; private set => Set(ref _summary, value); }

    /// <summary>Files the last scan skipped because they were unchanged since a clean scan.</summary>
    public int Unchanged { get; private set; }

    public static IReadOnlyList<string> QuickScanRoots()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roots = new List<string>
        {
            Path.Combine(home, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            Path.GetTempPath(),
        };
        return roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static IReadOnlyList<string> FullScanRoots() =>
        DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady).Select(d => d.RootDirectory.FullName).ToList();

    /// <summary>Executables of running processes we're allowed to inspect.</summary>
    private static IEnumerable<string> RunningExecutables()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            string? path = null;
            try { path = p.MainModule?.FileName; }
            catch (Exception) { /* protected or exited */ }
            finally { p.Dispose(); }
            if (path is not null && seen.Add(path)) yield return path;
        }
    }

    /// <param name="deep">Also rescan files that are unchanged since they last scanned clean.</param>
    public async Task RunAsync(ScanKind kind, IReadOnlyList<string>? customRoots = null, bool deep = false)
    {
        if (IsRunning) return;
        var roots = kind switch
        {
            ScanKind.Quick => QuickScanRoots(),
            ScanKind.Full => FullScanRoots(),
            _ => customRoots ?? [],
        };
        if (roots.Count == 0) return;

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        Kind = kind;
        IsRunning = true;
        FilesScanned = 0;
        Summary = "";
        Detections.Clear();
        _clock.Restart();
        AppServices.Activity.Add(LogKind.Scan, $"{kind} scan started", string.Join(", ", roots));

        int files = 0, unchanged = 0;
        long lastUi = 0;
        void OnFile(ScanResult r)
        {
            files++;
            if (r.Detail.StartsWith("Unchanged")) unchanged++;
            if (r.IsThreat) Ui.Post(() => Detections.Add(new Detection { Result = r }));
            long now = _clock.ElapsedMilliseconds;
            if (now - lastUi > 80)
            {
                lastUi = now;
                int f = files;
                Ui.Post(() =>
                {
                    FilesScanned = f;
                    CurrentPath = r.Path;
                    Elapsed = _clock.Elapsed.ToString(@"mm\:ss");
                });
            }
        }

        try
        {
            await Task.Run(() =>
            {
                if (kind == ScanKind.Quick)
                {
                    foreach (string exe in RunningExecutables())
                    {
                        if (token.IsCancellationRequested) return;
                        OnFile(Scanner.ScanFile(exe, deep));
                    }
                }
                foreach (string root in roots)
                {
                    if (token.IsCancellationRequested) return;
                    if (File.Exists(root)) OnFile(Scanner.ScanFile(root, fresh: true));
                    else if (Directory.Exists(root)) Scanner.ScanDirectory(root, OnFile, token, deep);
                }
            }, token);
        }
        catch (OperationCanceledException) { }

        _clock.Stop();
        bool cancelled = token.IsCancellationRequested;
        await Ui.Dispatcher.InvokeAsync(() => { });  // flush queued detections before counting
        int threats = Detections.Count;
        FilesScanned = files;
        Elapsed = _clock.Elapsed.ToString(@"mm\:ss");
        CurrentPath = "";
        IsRunning = false;
        Unchanged = unchanged;
        string skipped = unchanged > 0 ? $" ({unchanged:N0} unchanged, skipped)" : "";
        Summary = $"{(cancelled ? "Stopped" : "Finished")} · {files:N0} file{(files == 1 ? "" : "s")}{skipped} · {threats} threat{(threats == 1 ? "" : "s")} · {Elapsed}";
        _ = Task.Run(AppServices.SaveScanCache);

        var s = AppServices.Settings;
        if (!cancelled)
        {
            s.LastScan = DateTimeOffset.Now;
            s.LastScanFiles = files;
            s.LastScanThreats = threats;
            s.Save();
        }
        AppServices.Activity.Add(threats > 0 ? LogKind.Threat : LogKind.Scan,
            $"{kind} scan {(cancelled ? "stopped" : "complete")}",
            $"{files:N0} file{(files == 1 ? "" : "s")} checked, {threats} threat{(threats == 1 ? "" : "s")} found");
        AppServices.Raise();
        if (threats > 0)
            AppServices.Tray?.Notify("Threats found", $"{kind} scan found {threats} item{(threats == 1 ? "" : "s")} that need attention.", warning: true);
    }

    public void Stop() => _cts?.Cancel();

    public static bool QuarantineDetection(Detection d)
    {
        try
        {
            Quarantine.Add(d.Result.Path, VeylPaths.QuarantineDir, d.Result.Threat);
            d.State = "Quarantined";
            AppServices.Activity.Add(LogKind.Quarantine, $"Quarantined {d.FileName}", d.Result.Threat);
            AppServices.Raise();
            return true;
        }
        catch (VeylException ex)
        {
            d.State = ex.Status == VeylStatus.IoError ? "Couldn't quarantine: file in use or access denied" : ex.Message;
            return false;
        }
    }
}
