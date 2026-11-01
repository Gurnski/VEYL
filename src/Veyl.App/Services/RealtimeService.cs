using System.Collections.Concurrent;
using Veyl.Shared;

namespace Veyl.App.Services;

/// <summary>
/// Watches folders where new files usually land (Downloads, Desktop, Startup, Temp)
/// and scans risky file types once they've stopped changing. This is user-mode
/// monitoring, not a kernel filter: it reacts just after a file is written.
/// </summary>
public sealed class RealtimeService : Observable, IDisposable
{
    private static readonly HashSet<string> RiskyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".msp", ".sys", ".cpl", ".ocx",
        ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk",
    };
    private static readonly TimeSpan Settle = TimeSpan.FromSeconds(1.5);

    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentDictionary<string, DateTime> _pending = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;
    private int _busy;

    private bool _active;
    public bool IsActive { get => _active; private set => Set(ref _active, value); }

    private int _checked;
    public int FilesChecked { get => _checked; private set => Set(ref _checked, value); }

    private int _blocked;
    public int ThreatsBlocked { get => _blocked; private set => Set(ref _blocked, value); }

    public void Apply(UserSettings s)
    {
        Stop();
        if (!s.RealtimeEnabled) return;
        foreach (string folder in s.WatchedFolders.Where(Directory.Exists))
        {
            var w = new FileSystemWatcher(folder)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
            };
            w.Created += (_, e) => Queue(e.FullPath);
            w.Changed += (_, e) => Queue(e.FullPath);
            w.Renamed += (_, e) => Queue(e.FullPath);
            w.Error += (_, _) => Ui.Post(() => Apply(AppServices.Settings));  // buffer overflow: restart
            w.EnableRaisingEvents = true;
            _watchers.Add(w);
        }
        _timer = new Timer(_ => Drain(), null, 500, 500);
        IsActive = _watchers.Count > 0;
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
        foreach (var w in _watchers) w.Dispose();
        _watchers.Clear();
        _pending.Clear();
        IsActive = false;
    }

    private void Queue(string path)
    {
        if (RiskyExtensions.Contains(Path.GetExtension(path)) &&
            !path.StartsWith(VeylPaths.Root, StringComparison.OrdinalIgnoreCase))
            _pending[path] = DateTime.UtcNow;
    }

    private void Drain()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var now = DateTime.UtcNow;
            foreach (var (path, seen) in _pending)
            {
                if (now - seen < Settle) continue;  // still being written
                _pending.TryRemove(path, out _);
                if (File.Exists(path)) Check(path);
            }
        }
        finally { Volatile.Write(ref _busy, 0); }
    }

    private void Check(string path)
    {
        ScanResult r;
        try { r = Scanner.ScanFile(path, fresh: true); }  // new or changed file: never trust the cache
        catch (VeylException) { return; }
        Ui.Post(() => FilesChecked++);
        if (!r.IsThreat) return;

        string name = Path.GetFileName(path);
        var settings = AppServices.Settings;
        if (r.Verdict == Verdict.Malicious && settings.AutoQuarantine)
        {
            try
            {
                Quarantine.Add(path, VeylPaths.QuarantineDir, r.Threat);
                Ui.Post(() => ThreatsBlocked++);
                AppServices.Activity.Add(LogKind.Realtime, $"Blocked {name}", $"{r.Threat} — moved to quarantine");
                AppServices.Tray?.Notify("Threat blocked", $"{name} ({r.Threat}) was moved to quarantine.", warning: true);
                AppServices.Raise();
                return;
            }
            catch (VeylException) { /* fall through to a warning */ }
        }

        AppServices.Activity.Add(LogKind.Threat, $"{(r.Verdict == Verdict.Malicious ? "Threat" : "Suspicious file")}: {name}",
            $"{r.Threat} — {r.Detail}");
        AppServices.Tray?.Notify(r.Verdict == Verdict.Malicious ? "Threat detected" : "Suspicious file",
            $"{name}: {r.Threat}. Open VEYL to review it.", warning: true);
    }

    public void Dispose() => Stop();
}
