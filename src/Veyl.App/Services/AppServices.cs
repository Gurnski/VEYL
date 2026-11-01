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
        _ = Task.Run(EnsureModernMenu);
    }

    /// <summary>
    /// Packages register per user, and setup can only do it for the user who installed VEYL.
    /// Everyone else gets the Windows 11 menu entries here, once per version.
    /// </summary>
    private static void EnsureModernMenu()
    {
        try
        {
            if (!ModernMenu.Supported || Manifest is null || Settings.MenuPackageVersion == Version) return;
            // Setup writes the classic entries only when the menu option is ticked; follow that choice.
            using var classic = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Classes\*\shell\VEYL.Scan");
            if (classic is null || !File.Exists(ModernMenu.PackagePath(VeylPaths.InstallDir))) return;
            string? error = ModernMenu.Register(VeylPaths.InstallDir, Version);
            if (error is null)
            {
                Settings.MenuPackageVersion = Version;
                Settings.Save();
            }
            else
            {
                Activity.Add(LogKind.System, "Couldn't add VEYL to the Windows 11 right-click menu", error);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Only the shortcut menu; the "Show more options" entries still work.
        }
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
            Version = "0.2.5",
            Date = "2026-11-01",
            Notes =
            [
                "\"Run in VEYL sandbox\" and \"Scan with VEYL\" in Windows 11's main right-click menu",
                "The sandbox now records what 32-bit programs do, including older installers",
                "VEYL checks for updates every 6 hours while it runs, and About has \"Check for updates\"",
                "\"Download and install\" fetches the new version and checks it before running it",
            ],
        },
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
