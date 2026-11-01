using System.Windows;
using System.Windows.Threading;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App;

public partial class App : Application
{
    private Mutex? _instance;
    private EventWaitHandle? _showEvent;
    private MainWindow? _main;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Setup runs this after installing to prove the install works. No UI, no single-instance lock.
        if (e.Args.Length > 0 && e.Args[0] == "--selftest")
        {
            Shutdown(SelfTest.Run(e.Args.ElementAtOrDefault(1)));
            return;
        }

        _instance = InstanceNames.CreateAppMutex(out bool first);
        if (!first)
        {
            // Pass our command line (e.g. --scan from Explorer) to the running copy.
            if (e.Args.Length == 0 || !AppCommands.TrySend(e.Args)) InstanceNames.SignalShow();
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandled;
        bool tray = e.Args.Contains("--tray", StringComparer.OrdinalIgnoreCase);
        AppServices.UpdateVersion = e.Args.FirstOrDefault(a => a.StartsWith("--update="))?["--update=".Length..];

        try
        {
            AppServices.Start();
        }
        catch (Exception ex) when (ex is DllNotFoundException or BadImageFormatException)
        {
            MessageBox.Show("Veyl.Core.dll is missing or damaged. Reinstall VEYL.\n\n" + ex.Message, "VEYL",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        AppServices.Tray = new TrayIcon(ShowMain, QuickScan, ExitApp);
        _main = new MainWindow();
        // --page=shield/scan opens straight to a page.
        if (e.Args.FirstOrDefault(a => a.StartsWith("--page="))?["--page=".Length..].Split('/') is [var ws, var page])
            _main.Navigate(ws, page);
        if (!tray || !AppServices.Settings.StartMinimized) ShowMain();

        ListenForShowRequests();
        AppCommands.Listen(args => Dispatcher.BeginInvoke(() => HandleCommand(args)), CancellationToken.None);
        HandleCommand(e.Args);
        SignalReady();
    }

    /// <summary>Acts on a command line from our own start-up or a later launch.</summary>
    private void HandleCommand(string[] args)
    {
        int s = Array.IndexOf(args, "--sandbox");
        if (s >= 0 && s + 1 < args.Length)
        {
            ShowMain();
            _main?.SandboxFile(args[s + 1]);
            return;
        }

        int i = Array.IndexOf(args, "--scan");
        if (i >= 0 && i + 1 < args.Length)
        {
            string target = args[i + 1];
            ShowMain();
            _main?.Navigate("shield", "scan");
            if (AppServices.Scan.IsRunning)
                _main?.ShowToast("A scan is already running");
            else
                _ = AppServices.Scan.RunAsync(ScanKind.Custom, [target]);
            return;
        }
        if (args.Length > 0 && !args.Contains("--tray")) ShowMain();
    }

    public void ShowMain()
    {
        if (_main is null) return;
        _main.Show();
        if (_main.WindowState == WindowState.Minimized) _main.WindowState = WindowState.Normal;
        _main.Activate();
        _main.Topmost = true;  // reliably come to the front when restored from the tray
        _main.Topmost = false;
        _main.Focus();
    }

    private void QuickScan()
    {
        ShowMain();
        _main?.Navigate("shield", "scan");
        _ = AppServices.Scan.RunAsync(ScanKind.Quick);
    }

    public void ExitApp()
    {
        AppServices.Stop();
        AppServices.Tray?.Dispose();
        Shutdown();
    }

    /// <summary>A second launch (or the launcher) sets this event to bring the window back.</summary>
    private void ListenForShowRequests()
    {
        _showEvent = InstanceNames.CreateEvent(InstanceNames.ShowEvent, EventResetMode.AutoReset);
        var thread = new Thread(() =>
        {
            while (_showEvent.WaitOne()) Dispatcher.BeginInvoke(ShowMain);
        }) { IsBackground = true, Name = "VEYL show listener" };
        thread.Start();
    }

    private static void SignalReady()
    {
        if (EventWaitHandle.TryOpenExisting(InstanceNames.ReadyEvent, out var ready))
        {
            ready.Set();
            ready.Dispose();
        }
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        AppServices.Activity.Add(LogKind.System, "Unexpected error", e.Exception.Message);
        MessageBox.Show(e.Exception.Message, "VEYL", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _instance?.Dispose();
        base.OnExit(e);
    }
}
