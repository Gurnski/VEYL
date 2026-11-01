using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Veyl.Shared;

namespace Veyl.Setup;

public partial class SetupWindow : Window
{
    private readonly bool _uninstallRequested;
    private Installer? _installer;
    private bool _busy;
    private Action? _retry;

    public SetupWindow(bool uninstallRequested)
    {
        InitializeComponent();
        WindowHelper.ApplyDarkRounded(this);
        _uninstallRequested = uninstallRequested;
        Loaded += (_, _) => ShowStart();
    }

    // ---------------------------------------------------------------- states

    private void ShowStart()
    {
        if (_uninstallRequested)
        {
            ShowUninstallConfirm();
            return;
        }

        string payload = Payload.Version;
        string? installed = Installer.InstalledVersion();
        long mb = Payload.UncompressedSize >> 20;
        Reset();
        Options.Visibility = Visibility.Visible;
        StatusRight.Text = "v" + payload;

        if (installed is not null)
        {
            // Start from what's set up now.
            StartupOpt.IsChecked = Installer.TaskExists();
            MenuOpt.IsChecked = Installer.MenuExists();
            DesktopOpt.IsChecked = Installer.DesktopLinkExists();
        }

        if (installed is null)
        {
            Set("Install VEYL", $"Antivirus and password vault for everyone who uses this PC. Installs to {Installer.TargetDir} ({mb} MB).");
            AddButton("Install", "PrimaryButton", () => RunInstall());
            AddButton("Cancel", null, Close);
        }
        else if (Manifest.IsNewer(payload, installed))
        {
            Set($"Update VEYL {installed} → {payload}", "Your vaults, quarantine and settings stay as they are.");
            AddButton("Update", "PrimaryButton", () => RunInstall());
            AddButton("Cancel", null, Close);
        }
        else if (installed == payload)
        {
            Set($"VEYL {installed} is installed", "Repair puts back missing or changed files and reapplies the options below.");
            AddButton("Repair", "PrimaryButton", () => RunInstall());
            AddButton("Uninstall", "DangerButton", ShowUninstallConfirm);
            AddButton("Close", null, Close);
        }
        else
        {
            Set($"VEYL {installed} is already installed", $"That's newer than this setup ({payload}). Installing would go back a version.");
            AddButton($"Install {payload} anyway", "SoftAccentButton", () => RunInstall());
            AddButton("Uninstall", "DangerButton", ShowUninstallConfirm);
            AddButton("Close", null, Close);
        }
    }

    private void ShowUninstallConfirm()
    {
        Reset();
        Set("Uninstall VEYL?", "Protection stops for every user on this PC. Vaults are kept unless you tick the box below.");
        StatusRight.Text = Installer.InstalledVersion() is { } v ? "v" + v : "";
        RemoveDataOpt.Visibility = Visibility.Visible;
        RemoveDataOpt.IsChecked = false;
        AddButton("Uninstall", "DangerButton", RunUninstall);
        if (!_uninstallRequested) AddButton("Back", null, ShowStart);
        else AddButton("Cancel", null, Close);
    }

    private void ShowProgress(SetupStep step)
    {
        if (step.Title == "Done") return;
        StatusTitle.Text = step.Title + "…";
        StatusDetail.Text = step.Detail;
        StatusRight.Text = $"Step {step.Index} of {step.Count}";
        Progress.SetProgress(step.Progress);
    }

    private void BeginWork()
    {
        Reset();
        _busy = true;
        CloseX.IsEnabled = false;
        Progress.Visibility = Visibility.Visible;
        Progress.FillBrush = (Brush)FindResource("TextBrush");
        Progress.Busy = true;
        Progress.SetProgress(0, animate: false);
    }

    private void EndWork()
    {
        _busy = false;
        CloseX.IsEnabled = true;
        Progress.Busy = false;
    }

    private void ShowError(Exception ex)
    {
        EndWork();
        _installer?.Log($"FAILED: {ex}");
        string title = ex is SetupFailed f ? f.Title : "Something went wrong";
        Set(title, ex.Message);
        StatusRight.Text = "";
        Progress.FillBrush = (Brush)FindResource("DangerBrush");
        Progress.SetProgress(1);
        Buttons.Children.Clear();
        AddButton("Try again", "PrimaryButton", () => _retry?.Invoke());
        AddButton("Close", null, Close);
        ShowLogLink();
    }

    // ---------------------------------------------------------------- actions

    private async void RunInstall()
    {
        var options = new SetupOptions(
            StartWithWindows: StartupOpt.IsChecked == true,
            DesktopShortcut: DesktopOpt.IsChecked == true,
            ExplorerMenu: MenuOpt.IsChecked == true);
        _retry = RunInstall;
        BeginWork();
        Set("Getting ready…", "");
        try
        {
            _installer = new Installer();
            await _installer.InstallAsync(options, s => Dispatcher.Invoke(() => ShowProgress(s)));
        }
        catch (Exception ex)
        {
            ShowError(ex);
            return;
        }
        EndWork();
        Progress.SetProgress(1);
        Set("VEYL is ready", options.StartWithWindows
            ? "Installed and verified. From now on VEYL starts whenever anyone signs in to this PC."
            : "Installed and verified. Start it from the Start menu whenever you like.");
        StatusRight.Text = "v" + Payload.Version;
        AddButton("Launch VEYL", "PrimaryButton", () =>
        {
            Installer.LaunchUnelevated();
            Close();
        });
        AddButton("Close", null, Close);
        ShowLogLink();
    }

    private async void RunUninstall()
    {
        var options = new SetupOptions(RemoveData: RemoveDataOpt.IsChecked == true);
        if (options.RemoveData &&
            MessageBox.Show(this, "Every user's password vault on this PC will be deleted for good. Continue?",
                "VEYL Setup", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        _retry = RunUninstall;
        BeginWork();
        Set("Getting ready…", "");
        try
        {
            _installer = new Installer();
            await _installer.UninstallAsync(options, s => Dispatcher.Invoke(() => ShowProgress(s)));
        }
        catch (Exception ex)
        {
            ShowError(ex);
            return;
        }
        EndWork();
        Progress.SetProgress(1);
        Set("VEYL has been removed", options.RemoveData
            ? "All program files and data are gone."
            : $"Your vaults and settings are still in {Installer.DataDir}, ready if you reinstall.");
        StatusRight.Text = "";
        AddButton("Close", "PrimaryButton", Close);
    }

    // ---------------------------------------------------------------- helpers

    private void Reset()
    {
        Buttons.Children.Clear();
        Options.Visibility = Visibility.Collapsed;
        RemoveDataOpt.Visibility = Visibility.Collapsed;
        Progress.Visibility = Visibility.Collapsed;
        LinkButton.Visibility = Visibility.Collapsed;
    }

    private void Set(string title, string detail)
    {
        StatusTitle.Text = title;
        StatusDetail.Text = detail;
    }

    private void AddButton(string text, string? style, Action onClick)
    {
        var b = new Button { Content = text, Margin = new Thickness(Buttons.Children.Count == 0 ? 0 : 8, 0, 0, 0), Padding = new(18, 9, 18, 9) };
        if (style is not null) b.Style = (Style)FindResource(style);
        b.Click += (_, _) => onClick();
        Buttons.Children.Add(b);
    }

    private void ShowLogLink()
    {
        if (_installer is null || !File.Exists(_installer.LogPath)) return;
        LinkButton.Content = "View log";
        LinkButton.Visibility = Visibility.Visible;
    }

    private void Link_Click(object sender, RoutedEventArgs e)
    {
        if (_installer is not null) Process.Start("notepad.exe", $"\"{_installer.LogPath}\"");
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (_busy) e.Cancel = true;  // never leave a half-finished install
        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
        Application.Current.Shutdown();
    }
}
