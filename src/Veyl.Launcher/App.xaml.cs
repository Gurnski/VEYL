using System.Windows;
using Veyl.Shared;

namespace Veyl.Launcher;

public partial class App : Application
{
    /// <summary>Started by the logon task: run checks without a window and start the app in the tray.</summary>
    public static bool Autostart { get; private set; }

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        Autostart = e.Args.Contains("--autostart", StringComparer.OrdinalIgnoreCase);

        if (InstanceNames.AppIsRunning())
        {
            if (!Autostart) InstanceNames.SignalShow();
            Shutdown();
            return;
        }

        if (Autostart)
        {
            if (!UserSettings.Load().StartWithWindows)
            {
                Shutdown();
                return;
            }
            LaunchResult result;
            try
            {
                result = await new LaunchSequence().RunAsync(_ => { });
            }
            catch (Exception)
            {
                // No window to report to at sign-in; fall back to starting the app (it checks its own core DLL).
                result = new(true, "", "");
            }
            // A failed integrity check deliberately stops here: a tampered build should not autostart.
            if (result.Ok) LaunchSequence.StartApp(tray: true, result.UpdateVersion);
            Shutdown();
            return;
        }

        var window = new LauncherWindow();
        window.Show();
    }
}
