using System.Windows.Controls;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

public partial class AboutPage : UserControl, IRefreshable
{
    public AboutPage()
    {
        InitializeComponent();
        AppServices.StateChanged += () => { if (IsVisible) RefreshUpdates(); };
    }

    private void RefreshUpdates()
    {
        var u = AppServices.Updates;
        CheckButton.Visibility = UpdateChecker.Enabled ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
        CheckButton.IsEnabled = !u.IsChecking;
        CheckButton.Content = AppServices.UpdateVersion is null ? "Check for updates" : "Download and install";

        if (!UpdateChecker.Enabled)
        {
            UpdateStatus.Text = "Update checks are off";
            UpdateDetail.Text = AppServices.Manifest is null ? "Development builds don't check for releases." : "This build was made without an update address.";
        }
        else if (u.IsChecking)
        {
            UpdateStatus.Text = "Checking…";
            UpdateDetail.Text = "Asking GitHub for the latest release.";
        }
        else if (AppServices.UpdateVersion is { } v)
        {
            UpdateStatus.Text = $"VEYL {v} is available";
            UpdateDetail.Text = "Download and install it from the Overview page.";
        }
        else
        {
            UpdateStatus.Text = u.LastError is null ? "Up to date" : "Couldn't check for updates";
            string when = u.LastChecked is null ? "Checked when VEYL started" : $"Checked {Ui.Ago(u.LastChecked)}";
            UpdateDetail.Text = u.LastError is null
                ? $"{when}. VEYL checks again every {UpdateChecker.Interval.TotalHours:0} hours while it runs."
                : $"{when}: {u.LastError}";
        }
    }

    private async void Check_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        if (AppServices.UpdateVersion is not null)
        {
            MainWindow.Current?.Navigate("home", "overview");
            return;
        }
        if (await AppServices.Updates.CheckAsync() is null && AppServices.Updates.LastError is null)
            MainWindow.Current?.ShowToast("VEYL is up to date");
    }

    public void Refresh()
    {
        var m = AppServices.Manifest;
        AppTile.Value = AppServices.Version;
        AppTile.Note = m?.Channel ?? "development";
        CoreTile.Value = Core.Version;
        InstallTile.Value = VeylPaths.InstallDir.TrimEnd('\\');
        DataTile.Value = VeylPaths.Root;
        UserTile.Value = VeylPaths.UserName;
        UserTile.Note = VeylPaths.UserSid;
        BuildTile.Value = m is null ? "Not from a release build" : m.BuildDate;
        BuildTile.Note = m is null ? "No manifest.json, so integrity checks are off" : $"{m.Files.Count} files verified at launch";
        RefreshUpdates();
    }
}
