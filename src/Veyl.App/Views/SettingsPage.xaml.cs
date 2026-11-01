using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using Veyl.App.Services;

namespace Veyl.App.Views;

public partial class SettingsPage : UserControl, IRefreshable
{
    public SettingsPage() => InitializeComponent();

    public async void Refresh()
    {
        var s = AppServices.Settings;
        StartupToggle.IsChecked = s.StartWithWindows;
        MinimizedToggle.IsChecked = s.StartMinimized;
        TrayToggle.IsChecked = s.CloseToTray;
        NotifyToggle.IsChecked = s.Notifications;
        TaskNote.Text = "";
        TaskNote.Text = await Task.Run(LogonTaskInstalled)
            ? "The VEYL sign-in task is installed for every user on this PC. Turning off Start with Windows only affects your account."
            : "The sign-in task isn't installed yet. Run install.ps1 as administrator to start VEYL automatically.";
    }

    private static bool LogonTaskInstalled()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("schtasks.exe", "/Query /TN \"VEYL\\Launcher\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            p!.WaitForExit(3000);
            return p.ExitCode == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private void Toggle_Click(object sender, RoutedEventArgs e)
    {
        var s = AppServices.Settings;
        s.StartWithWindows = StartupToggle.IsChecked == true;
        s.StartMinimized = MinimizedToggle.IsChecked == true;
        s.CloseToTray = TrayToggle.IsChecked == true;
        s.Notifications = NotifyToggle.IsChecked == true;
        s.Save();
    }

    private async void Quit_Click(object sender, RoutedEventArgs e)
    {
        if (await MainWindow.Current!.ConfirmAsync("Quit VEYL?",
                "Real-time protection stops and the vault locks until you start VEYL again.", "Quit", danger: true))
            ((App)Application.Current).ExitApp();
    }
}
