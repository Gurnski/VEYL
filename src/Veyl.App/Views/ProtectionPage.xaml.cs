using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

public partial class ProtectionPage : UserControl, IRefreshable
{
    public ProtectionPage()
    {
        InitializeComponent();
        AppServices.Realtime.PropertyChanged += (_, _) => { if (IsVisible) RefreshStats(); };
    }

    public void Refresh()
    {
        var s = AppServices.Settings;
        RealtimeToggle.IsChecked = s.RealtimeEnabled;
        AutoQuarantineToggle.IsChecked = s.AutoQuarantine;
        AmsiToggle.IsChecked = s.UseAmsi;
        Folders.ItemsSource = s.WatchedFolders.ToList();
        RefreshStats();
    }

    private void RefreshStats()
    {
        var rt = AppServices.Realtime;
        StateTile.Value = rt.IsActive ? "On" : "Off";
        StateTile.ValueBrush = (Brush)FindResource(rt.IsActive ? "GoodBrush" : "WarnBrush");
        StateTile.Note = rt.IsActive ? $"{AppServices.Settings.WatchedFolders.Count(Directory.Exists)} folders watched" : "Not watching";
        CheckedTile.Value = rt.FilesChecked.ToString("N0");
        BlockedTile.Value = rt.ThreatsBlocked.ToString("N0");
    }

    private void Apply()
    {
        var s = AppServices.Settings;
        s.Save();
        AppServices.Realtime.Apply(s);
        AppServices.Raise();
        Refresh();
    }

    private void Toggle_Click(object sender, RoutedEventArgs e)
    {
        var s = AppServices.Settings;
        bool amsiChanged = s.UseAmsi != (AmsiToggle.IsChecked == true);
        s.RealtimeEnabled = RealtimeToggle.IsChecked == true;
        s.AutoQuarantine = AutoQuarantineToggle.IsChecked == true;
        s.UseAmsi = AmsiToggle.IsChecked == true;
        if (amsiChanged) Scanner.Init(VeylPaths.SignatureFile, s.UseAmsi);
        AppServices.Activity.Add(LogKind.Realtime, "Protection settings changed",
            $"Real-time {(s.RealtimeEnabled ? "on" : "off")}, auto-quarantine {(s.AutoQuarantine ? "on" : "off")}, AMSI {(s.UseAmsi ? "on" : "off")}");
        Apply();
    }

    private void Add_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "Watch a folder", Multiselect = true };
        if (dlg.ShowDialog() != true) return;
        var s = AppServices.Settings;
        foreach (string f in dlg.FolderNames)
            if (!s.WatchedFolders.Contains(f, StringComparer.OrdinalIgnoreCase)) s.WatchedFolders.Add(f);
        Apply();
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        AppServices.Settings.WatchedFolders.Remove((string)((FrameworkElement)sender).DataContext);
        Apply();
    }

    private void Reset_Click(object sender, RoutedEventArgs e)
    {
        AppServices.Settings.WatchedFolders = UserSettings.DefaultWatchedFolders();
        Apply();
    }
}
