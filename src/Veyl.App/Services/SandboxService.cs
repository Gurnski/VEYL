using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text.Json;
using System.Windows.Threading;
using Veyl.Shared;

namespace Veyl.App.Services;

public enum SandboxState { Running, Finished, Stopped, TimedOut, Failed }

public enum Severity { Info, Low, Medium, High }

/// <summary>One line of events.jsonl written by Veyl.SandboxHook.dll.</summary>
public sealed class SandboxEvent
{
    public required long Tick { get; init; }
    public required int Pid { get; init; }
    public required string Op { get; init; }
    public required Dictionary<string, string> Fields { get; init; }
    public TimeSpan At { get; set; }

    public string Get(string key) => Fields.TryGetValue(key, out var v) ? v : "";
    public string Result => Get("result");
    public bool Blocked => Result == "blocked";

    public string Category => Op.Split('.')[0] switch
    {
        "file" => "Files",
        "reg" => "Registry",
        "proc" or "inject" or "driver" => "Processes",
        "net" => "Network",
        _ => "Other",
    };

    public string Glyph => Op switch
    {
        "file.create" => "",
        "file.write" => "",
        "file.delete" => "",
        "file.rename" => "",
        "reg.write" or "reg.setvalue" or "reg.delete" => "",
        "proc.start" => "",
        "proc.create" => "",
        "proc.open" => "",
        "net.connect" => "",
        "driver.load" => "",
        _ when Op.StartsWith("inject") => "",
        _ => "",
    };

    public string Title => Op switch
    {
        "file.create" => "Created file",
        "file.write" => "Changed file",
        "file.delete" => "Deleted file",
        "file.rename" => "Renamed file",
        "reg.write" => "Opened registry key to write",
        "reg.setvalue" => "Set registry value",
        "reg.delete" => "Deleted registry entry",
        "proc.start" => "Process started",
        "proc.create" => "Started a program",
        "proc.open" => "Opened another process",
        "inject.write" => "Wrote into another process",
        "inject.thread" => "Started a thread in another process",
        "inject.apc" => "Queued code into another process",
        "driver.load" => "Tried to load a driver",
        "net.connect" => "Connected to the internet",
        "monitor.gap" => "Monitor couldn't watch a call",
        _ => Op,
    };

    public string Detail => Op switch
    {
        "file.rename" => $"{Get("path")}  →  {Get("to")}",
        "reg.setvalue" => $"{Get("key")}  ·  {Get("value")} = {Get("data")}",
        "reg.delete" => Get("value").Length > 0 ? $"{Get("key")}  ·  {Get("value")}" : Get("key"),
        "proc.start" or "proc.create" => Get("cmdline").Length > 0 ? Get("cmdline") : Get("image"),
        "net.connect" => Get("address"),
        "driver.load" => Get("service"),
        _ when Op.StartsWith("inject") || Op == "proc.open" => $"Process {Get("target")}",
        "monitor.gap" => Get("call"),
        _ => Get("path").Length > 0 ? Get("path") : Get("key"),
    };

    /// <summary>Plain-language outcome: what actually happened to your PC.</summary>
    public string Outcome => Result switch
    {
        "sandboxed" => "kept in sandbox",
        "blocked" => "blocked",
        "ok" when Category is "Registry" => "allowed (sandbox area)",
        "ok" => "",
        "allowed" => "allowed",
        "" => "",
        var r => r,
    };

    public static SandboxEvent? Parse(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            var fields = new Dictionary<string, string>();
            foreach (var p in root.EnumerateObject())
                if (p.Name is not ("t" or "pid" or "op")) fields[p.Name] = p.Value.GetString() ?? "";
            return new SandboxEvent
            {
                Tick = root.GetProperty("t").GetInt64(),
                Pid = root.GetProperty("pid").GetInt32(),
                Op = root.GetProperty("op").GetString() ?? "",
                Fields = fields,
            };
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return null;
        }
    }
}

public sealed record SandboxFinding(Severity Severity, string Title, string Detail)
{
    public string Label => Severity.ToString().ToUpperInvariant();
}

/// <summary>One sandboxed run: the program, its live event stream and what VEYL makes of it.</summary>
public sealed class SandboxRun : Observable
{
    public required string Id { get; init; }
    public required string ExePath { get; init; }
    public required string Root { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public ScanResult? StaticScan { get; init; }
    public string Name => Path.GetFileName(ExePath);

    public ObservableCollection<SandboxEvent> Events { get; } = [];
    public ObservableCollection<SandboxFinding> Findings { get; } = [];

    private SandboxState _state;
    public SandboxState State { get => _state; set { if (Set(ref _state, value)) Raise(nameof(IsRunning)); } }
    public bool IsRunning => _state == SandboxState.Running;

    private int _processes;
    public int Processes { get => _processes; set => Set(ref _processes, value); }

    private string _elapsed = "0.0s";
    public string Elapsed { get => _elapsed; set => Set(ref _elapsed, value); }

    private bool _monitored = true;
    public bool Monitored { get => _monitored; set => Set(ref _monitored, value); }

    private int _score;
    public int Score { get => _score; set { if (Set(ref _score, value)) Raise(nameof(Verdict)); } }

    public string Verdict => _score switch
    {
        >= 70 => "Behaves like malware",
        >= 35 => "Suspicious behaviour",
        _ => "Nothing harmful seen",
    };

    public string ExitInfo { get; set; } = "";

    /// <summary>Set when the monitor never reported in (the program may be stuck starting up).</summary>
    public bool MonitorSilent { get; set; }
}

/// <summary>Runs programs in the VEYL sandbox and follows what they do.</summary>
public sealed class SandboxService : Observable
{
    public static readonly TimeSpan TimeLimit = TimeSpan.FromMinutes(5);
    private readonly Dictionary<string, (SandboxProcess Proc, long Offset, Stopwatch Clock, long FirstTick, string? FirewallRule)> _live = [];
    private readonly DispatcherTimer _poll = new() { Interval = TimeSpan.FromMilliseconds(400) };

    public ObservableCollection<SandboxRun> Runs { get; } = [];

    private SandboxRun? _current;
    public SandboxRun? Current { get => _current; set => Set(ref _current, value); }

    public static string SandboxesDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow", "VEYL", "Sandbox");

    public static string HookDll => Path.Combine(VeylPaths.InstallDir, "Veyl.SandboxHook.dll");

    public SandboxService() => _poll.Tick += (_, _) => Poll();

    /// <summary>What to actually launch for a given file (scripts run through their host).</summary>
    public static (string Exe, string Args)? Launcher(string file, string args)
    {
        string sys = Environment.SystemDirectory;
        return Path.GetExtension(file).ToLowerInvariant() switch
        {
            ".exe" or ".com" or ".scr" => (file, args),
            ".bat" or ".cmd" => (Path.Combine(sys, "cmd.exe"), $"/c \"{file}\" {args}"),
            ".ps1" => (Path.Combine(sys, @"WindowsPowerShell\v1.0\powershell.exe"), $"-NoProfile -ExecutionPolicy Bypass -File \"{file}\" {args}"),
            ".vbs" or ".js" or ".wsf" => (Path.Combine(sys, "wscript.exe"), $"\"{file}\" {args}"),
            _ => null,
        };
    }

    public SandboxRun Start(string file, string args = "", bool allowNetwork = false)
    {
        var target = Launcher(file, args) ?? throw new InvalidOperationException(
            $"VEYL can sandbox programs (.exe) and scripts (.bat, .cmd, .ps1, .vbs, .js), not {Path.GetExtension(file)} files.");
        if (!File.Exists(HookDll)) throw new InvalidOperationException("Veyl.SandboxHook.dll is missing. Reinstall VEYL.");

        string id = $"{DateTime.Now:yyyyMMdd-HHmmss}-{Path.GetFileNameWithoutExtension(file)}";
        string root = Path.Combine(SandboxesDir, id);
        Directory.CreateDirectory(root);

        ScanResult? scan = null;
        try { scan = Scanner.ScanFile(file, fresh: true); } catch (VeylException) { }

        var run = new SandboxRun { Id = id, ExePath = file, Root = root, StartedAt = DateTimeOffset.Now, StaticScan = scan };
        SandboxProcess proc;
        try { proc = SandboxProcess.Start(target.Exe, target.Args, root, HookDll, allowNetwork); }
        catch (VeylException)
        {
            try { Directory.Delete(root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            throw;
        }
        run.Monitored = proc.Monitored;
        if (scan is { IsThreat: true })
            run.Findings.Add(new(scan.Verdict == Verdict.Malicious ? Severity.High : Severity.Medium,
                "The scanner already flags this file", $"{scan.Threat}: {scan.Detail}"));
        if (!proc.Monitored)
            run.Findings.Add(new(Severity.Info, "Activity isn't recorded for this program",
                "It still runs isolated. VEYL watches 64-bit and 32-bit Windows programs, but not 32-bit .NET programs or ones built for ARM."));

        // Only firewall the file itself, never a shared host like cmd.exe or powershell.exe.
        string? rule = allowNetwork || target.Exe != file ? null : AddFirewallBlock(id, target.Exe);
        _live[id] = (proc, 0, Stopwatch.StartNew(), 0, rule);
        Runs.Insert(0, run);
        Current = run;
        Analyse(run);
        _poll.Start();
        AppServices.Activity.Add(LogKind.Realtime, $"Sandboxed {run.Name}", file);
        return run;
    }

    public void Stop(SandboxRun run)
    {
        if (_live.TryGetValue(run.Id, out var l)) l.Proc.Kill();
        Finish(run, SandboxState.Stopped);
    }

    /// <summary>Deletes everything the program wrote. Its run stays in the list.</summary>
    public void Discard(SandboxRun run)
    {
        if (run.IsRunning) Stop(run);
        try { Directory.Delete(run.Root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        Runs.Remove(run);
        if (Current == run) Current = Runs.FirstOrDefault();
    }

    public void StopAll()
    {
        foreach (var run in Runs.Where(r => r.IsRunning).ToList()) Stop(run);
    }

    /// <summary>Plain-English note for exit codes that usually mean "the sandbox stopped it", not "it's broken".</summary>
    public static string DescribeExit(int code) => code switch
    {
        0 => "Exited normally",
        1601 or 1631 => $"Exited with code {code}: it needs the Windows Installer service, which can't run inside the sandbox",
        5 or 740 => $"Exited with code {code}: it probably wanted admin rights, which the sandbox takes away",
        _ => $"Exited with code {code} (0x{code:X8})",
    };

    private void Poll()
    {
        foreach (var run in Runs.Where(r => r.IsRunning).ToList())
        {
            var l = _live[run.Id];
            ReadEvents(run, ref l);
            _live[run.Id] = l;
            var (active, total, code) = l.Proc.Status();
            run.Processes = active;
            if (run.Monitored && !run.MonitorSilent && run.Events.Count == 0 && l.Clock.Elapsed > TimeSpan.FromSeconds(10))
            {
                run.MonitorSilent = true;
                Analyse(run);
            }
            run.Elapsed = FormatElapsed(l.Clock.Elapsed);
            if (active == 0)
            {
                run.ExitInfo = DescribeExit(code);
                Finish(run, SandboxState.Finished);
            }
            else if (l.Clock.Elapsed > TimeLimit)
            {
                l.Proc.Kill();
                Finish(run, SandboxState.TimedOut);
            }
        }
        if (!Runs.Any(r => r.IsRunning)) _poll.Stop();
    }

    private void ReadEvents(SandboxRun run, ref (SandboxProcess Proc, long Offset, Stopwatch Clock, long FirstTick, string? FirewallRule) l)
    {
        string file = Path.Combine(run.Root, "events.jsonl");
        if (!File.Exists(file)) return;
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length <= l.Offset) return;
            fs.Seek(l.Offset, SeekOrigin.Begin);
            using var r = new StreamReader(fs);
            string? line;
            bool added = false;
            while ((line = r.ReadLine()) is not null)
            {
                if (SandboxEvent.Parse(line) is not { } e) continue;
                if (l.FirstTick == 0) l.FirstTick = e.Tick;
                e.At = TimeSpan.FromMilliseconds(e.Tick - l.FirstTick);
                run.Events.Add(e);
                added = true;
            }
            l.Offset = fs.Length;
            if (added) Analyse(run);
        }
        catch (IOException) { /* mid-write; next poll */ }
    }

    private void Finish(SandboxRun run, SandboxState state)
    {
        if (!run.IsRunning) return;
        if (_live.TryGetValue(run.Id, out var l))
        {
            run.Elapsed = FormatElapsed(l.Clock.Elapsed);
            ReadEvents(run, ref l);
            l.Proc.Dispose();
            if (l.FirewallRule is not null) RemoveFirewallBlock(l.FirewallRule);
            _live.Remove(run.Id);
        }
        run.State = state;
        run.Processes = 0;
        Analyse(run);
        AppServices.Activity.Add(run.Score >= 70 ? LogKind.Threat : LogKind.Realtime,
            $"Sandbox run of {run.Name} ended", $"{run.Verdict} · {run.Events.Count} actions recorded");
        if (run.Score >= 70)
            AppServices.Tray?.Notify("Malware-like behaviour", $"{run.Name} behaved like malware in the sandbox. Nothing reached your PC.", warning: true);
    }

    // ------------------------------------------------------------ verdict

    private static readonly string[] PersistenceKeys =
    [
        @"\currentversion\run", @"\currentversion\runonce", @"\currentversion\policies\explorer\run",
        @"\winlogon", @"\image file execution options", @"\currentversion\explorer\user shell folders",
        @"\currentcontrolset\services\",  // a new service; system noise is filtered out below
    ];

    // Keys that ordinary Windows components open for writing in almost every program.
    private static readonly string[] NoiseKeys =
    [
        @"\services\winsock2", @"\services\tcpip", @"\services\dnscache", @"\services\bam", @"\internet settings",
        @"\control\nls", @"\software\microsoft\rpc", @"\local settings\", @"\currentversion\explorer\fileexts",
        @"\currentversion\explorer\mountpoints2",
    ];

    private static bool IsNoise(SandboxEvent e) =>
        e.Category == "Registry" && NoiseKeys.Any(k => e.Get("key").Contains(k, StringComparison.OrdinalIgnoreCase));

    private static readonly (string Needle, string What)[] NastyCommands =
    [
        ("vssadmin delete", "delete backups (shadow copies)"), ("vssadmin resize", "shrink backups (shadow copies)"),
        ("shadowcopy delete", "delete backups (shadow copies)"), ("wbadmin delete", "delete backups"), ("bcdedit", "change boot settings"),
        ("set-mppreference", "turn off Windows Defender"), ("add-mppreference", "add Defender exclusions"),
        ("schtasks", "schedule itself to run"), ("reg add", "edit the registry"), ("netsh advfirewall", "change the firewall"),
        ("cipher /w", "wipe free disk space"), ("-encodedcommand", "run hidden PowerShell"), ("powershell -e", "run hidden PowerShell"),
        ("certutil -urlcache", "download files"), ("bitsadmin", "download files"), ("mshta", "run HTML applications"),
        ("rundll32", "run code from a DLL"), ("regsvr32 /s /i", "run remote scripts"),
    ];

    private static void Analyse(SandboxRun run)
    {
        var events = run.Events;
        var found = new List<SandboxFinding>();
        int score = run.StaticScan is { Verdict: Verdict.Malicious } ? 70 : run.StaticScan is { Verdict: Verdict.Suspicious } ? 30 : 0;
        void Add(Severity s, int pts, string title, string detail)
        {
            score += pts;
            found.Add(new(s, title, detail));
        }

        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).ToLowerInvariant();
        string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup).ToLowerInvariant();
        string temp = Path.GetTempPath().TrimEnd('\\').ToLowerInvariant();

        var persistence = events.Where(e => e.Category == "Registry" && !IsNoise(e) && PersistenceKeys.Any(k => e.Get("key").ToLowerInvariant().Contains(k)))
            .Select(e => e.Get("key")).Concat(events.Where(e => e.Category == "Files" && e.Get("path").ToLowerInvariant().StartsWith(startup))
            .Select(e => e.Get("path"))).Distinct().ToList();
        if (persistence.Count > 0)
            Add(Severity.High, 40, "Tries to start itself with Windows", string.Join("\n", persistence.Take(4)));

        var injections = events.Where(e => e.Op.StartsWith("inject") || (e.Op == "proc.open" && e.Get("access") == "write")).ToList();
        if (injections.Count > 0)
            Add(Severity.High, 45, "Tries to inject code into other programs", $"{injections.Count} attempt(s), e.g. {injections[0].Title.ToLowerInvariant()}");

        if (events.Any(e => e.Op == "driver.load"))
            Add(Severity.High, 50, "Tries to load a kernel driver", "Malware uses drivers to hide or to switch off security software.");

        // cmd echoes commands with doubled spaces ("reg  add"); normalise before matching.
        var children = events.Where(e => e.Op == "proc.create")
            .Select(e => System.Text.RegularExpressions.Regex.Replace(e.Get("cmdline").ToLowerInvariant(), @"\s+", " ")).ToList();
        foreach (var (needle, what) in NastyCommands)
        {
            string? hit = children.FirstOrDefault(c => c.Contains(needle));
            if (hit is not null) Add(Severity.High, 35, $"Runs a command to {what}", hit);
        }

        var userFileChanges = events.Where(e => e.Op is "file.write" or "file.delete" or "file.rename")
            .Select(e => e.Get("path").ToLowerInvariant())
            .Where(p => p.StartsWith(home + @"\") && !p.StartsWith(temp) && !p.Contains(@"\appdata\")).Distinct().ToList();
        if (userFileChanges.Count >= 20)
            Add(Severity.High, 45, "Changes lots of your files", $"{userFileChanges.Count} of your files were modified, renamed or deleted, which is typical of ransomware.");
        else if (userFileChanges.Count > 0)
            Add(Severity.Low, 5, "Changes your files", string.Join("\n", userFileChanges.Take(3)));

        // PowerShell always writes a __PSScriptPolicyTest_*.ps1 probe; that isn't the program dropping anything.
        var dropped = events.Where(e => e.Op == "file.create" && IsExecutable(e.Get("path"))
                                        && !e.Get("path").Contains("__PSScriptPolicyTest", StringComparison.OrdinalIgnoreCase))
            .Select(e => e.Get("path")).Distinct().ToList();
        if (dropped.Count > 0)
            Add(Severity.Medium, 20, "Drops new programs or scripts", string.Join("\n", dropped.Take(4)));

        var net = events.Where(e => e.Op == "net.connect").Select(e => e.Get("address")).Distinct().ToList();
        if (net.Count > 0)
            Add(Severity.Medium, 10, "Tries to reach the internet", $"{string.Join(", ", net.Take(5))}{(net.Count > 5 ? $" and {net.Count - 5} more" : "")}");

        if (children.Count > 0 && found.All(f => !f.Title.StartsWith("Runs a command")))
            Add(Severity.Low, 5, "Starts other programs", string.Join("\n", children.Take(3)));

        if (events.Count(e => e.Blocked && e.Category == "Registry" && !IsNoise(e)) >= 5)
            Add(Severity.Low, 5, "Tries to change system settings", "Several registry writes were refused.");

        if (run.MonitorSilent && events.Count == 0)
            found.Add(new(Severity.Info, "VEYL hasn't heard from the program yet",
                "It's still isolated, but the activity monitor hasn't reported in. It may be stuck starting up; Stop it if nothing happens."));

        // Keep the 32-bit / static scan notes added at start.
        foreach (var keep in run.Findings.Where(f => f.Title.StartsWith("Activity isn't") || f.Title.StartsWith("The scanner")).ToList())
            found.Insert(0, keep);

        run.Findings.Clear();
        foreach (var f in found.OrderByDescending(f => f.Severity)) run.Findings.Add(f);
        run.Score = Math.Min(score, 100);
    }

    private static string FormatElapsed(TimeSpan t) => t.TotalSeconds < 60 ? $"{t.TotalSeconds:0.0}s" : t.ToString(@"m\:ss");

    private static bool IsExecutable(string path) =>
        Path.GetExtension(path).ToLowerInvariant() is ".exe" or ".dll" or ".scr" or ".sys" or ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".lnk";

    // ------------------------------------------------------------ firewall (belt and braces)

    // The monitor already refuses connections; a firewall rule also covers programs
    // that bypass it. Only possible when VEYL runs elevated.
    private static string? AddFirewallBlock(string id, string exe)
    {
        if (!AppServices.IsElevated) return null;
        string name = $"VEYL Sandbox {id}";
        foreach (string dir in new[] { "out", "in" })
            Netsh($"advfirewall firewall add rule name=\"{name}\" dir={dir} action=block program=\"{exe}\" enable=yes");
        return name;
    }

    private static void RemoveFirewallBlock(string name) => Netsh($"advfirewall firewall delete rule name=\"{name}\"");

    private static void Netsh(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("netsh.exe", args) { CreateNoWindow = true, UseShellExecute = false });
            p?.WaitForExit(5000);
        }
        catch (Exception) { /* the hook still blocks connections */ }
    }
}
