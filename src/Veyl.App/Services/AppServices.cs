using System.Security.Principal;
using Veyl.Shared;

namespace Veyl.App.Services;

/// <summary>Process-wide services. Created once in App.OnStartup.</summary>
public static class AppServices
{
    public static UserSettings Settings { get; private set; } = new();
    public static ActivityLog Activity { get; } = new();
    public static ScanService Scan { get; } = new();
    public static RealtimeService Realtime { get; } = new();
    public static SandboxService Sandbox { get; } = new();
    public static UpdateChecker Updates { get; } = new();
    private static readonly CancellationTokenSource Stopping = new();
    public static VaultService Vault { get; private set; } = null!;
    public static TrayIcon? Tray { get; set; }
    public static Manifest? Manifest { get; private set; }

    /// <summary>Newer version reported by the launcher's update check, if any.</summary>
    public static string? UpdateVersion { get; set; }

    public static bool IsElevated { get; } = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public static string Version => Manifest?.Version ?? typeof(AppServices).Assembly.GetName().Version!.ToString(3);

    /// <summary>Raised when anything shown in the status chips or overview changes.</summary>
    public static event Action? StateChanged;
    public static void Raise() => Ui.Post(() => StateChanged?.Invoke());

    public static void Start()
    {
        VeylPaths.EnsureCreated();
        Settings = UserSettings.Load();
        Manifest = Shared.Manifest.Load(VeylPaths.InstallDir);
        Activity.Load();
        Vault = new VaultService();
        Scanner.Init(VeylPaths.SignatureFile, Settings.UseAmsi);
        Scanner.LoadCache(VeylPaths.ScanCacheFile);
        Realtime.Apply(Settings);
        Updates.Start(Stopping.Token);
    }

    public static void ReloadSignatures()
    {
        Scanner.Init(VeylPaths.SignatureFile, Settings.UseAmsi);
        Raise();
    }

    public static void SaveScanCache()
    {
        try { Scanner.SaveCache(VeylPaths.ScanCacheFile); }
        catch (Exception) { /* only a speed-up; never worth failing over */ }
    }

    public static void Stop()
    {
        Stopping.Cancel();
        Scan.Stop();
        Sandbox.StopAll();
        Realtime.Dispose();
        Vault?.Dispose();
        SaveScanCache();
        Scanner.Shutdown();
    }
}

public static class ReleaseNotes
{
    public static IReadOnlyList<ChangelogEntry> All =>
        AppServices.Manifest?.Changelog is { Count: > 0 } fromManifest ? fromManifest : BuiltIn;

    private static readonly List<ChangelogEntry> BuiltIn =
    [
        new()
        {
            Version = "0.2.0",
            Date = "2026-10-31",
            Notes =
            [
                "Sandbox: run programs isolated and see everything they try to do",
                "Vault recovery keys, and \"Forgot your master password?\"",
                "Scans run on several threads and skip files that haven't changed",
                "Drag files onto Scan or Sandbox; vault shortcuts (Ctrl+F, Ctrl+N, Ctrl+L)",
                "VEYL-Setup.exe installer with repair, update and uninstall",
            ],
        },
        new()
        {
            Version = "0.1.0",
            Date = "2026-10-31",
            Notes =
            [
                "First release: launcher, Shield and Vault",
                "Hash, AMSI and heuristic scanning with quarantine",
                "Real-time watching of Downloads, Desktop, Startup and Temp",
                "Per-user AES-256-GCM password vault with auto-lock",
            ],
        },
    ];
}
