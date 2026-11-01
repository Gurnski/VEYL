using System.Diagnostics;
using System.Windows;

namespace Veyl.Setup;

/// <summary>
/// VEYL-Setup.exe [--uninstall] [--silent] [--trust-cert] [--remove-data] [--no-startup] [--no-menu] [--desktop]
/// With --silent there's no window; the exit code is 0 on success, 1 on failure (see the log).
/// </summary>
public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var args = e.Args.Select(a => a.ToLowerInvariant()).ToHashSet();
        bool uninstall = args.Contains("--uninstall");
        SetupOptions.TrustCertificate = args.Contains("--trust-cert");

        // Can't delete the folder we're running from, so uninstall from a temp copy.
        if (uninstall && Environment.ProcessPath!.StartsWith(Installer.TargetDir, StringComparison.OrdinalIgnoreCase))
        {
            string copy = Path.Combine(Path.GetTempPath(), "VEYL-Setup-uninstall.exe");
            File.Copy(Environment.ProcessPath, copy, overwrite: true);
            Process.Start(new ProcessStartInfo(copy, e.Args) { UseShellExecute = false });
            Shutdown();
            return;
        }

        if (args.Contains("--silent"))
        {
            var options = new SetupOptions(
                StartWithWindows: !args.Contains("--no-startup"),
                DesktopShortcut: args.Contains("--desktop"),
                ExplorerMenu: !args.Contains("--no-menu"),
                RemoveData: args.Contains("--remove-data"));
            Installer? installer = null;
            try
            {
                installer = new Installer();
                if (uninstall) await installer.UninstallAsync(options, _ => { });
                else await installer.InstallAsync(options, _ => { });
                Shutdown(0);
            }
            catch (Exception ex)
            {
                installer?.Log($"FAILED: {ex}");
                Shutdown(1);
            }
            return;
        }

        new SetupWindow(uninstall).Show();
    }
}
