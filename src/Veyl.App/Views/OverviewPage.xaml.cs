using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

public partial class OverviewPage : UserControl, IRefreshable
{
    public OverviewPage()
    {
        InitializeComponent();
        AccountText.Text = VeylPaths.UserName;
        AvatarText.Text = VeylPaths.UserName[..1].ToUpperInvariant();
        AppServices.StateChanged += () => { if (IsVisible) Refresh(); };
        AppServices.Activity.Items.CollectionChanged += (_, _) => { if (IsVisible) RefreshActivity(); };
    }

    private Brush B(string key) => (Brush)FindResource(key);

    public void Refresh()
    {
        var s = AppServices.Settings;
        bool admin = AppServices.IsElevated;
        PrivilegeTile.Value = admin ? "Administrator" : "Standard";
        PrivilegeTile.ValueBrush = B(admin ? "InfoBrush" : "TextBrush");
        PrivilegeTile.Note = admin ? "Can scan and quarantine system files" : "System folders may be skipped";

        bool rt = AppServices.Realtime.IsActive;
        ProtectionText.Text = rt ? "Real-time protection on" : "Real-time protection off";
        ProtectionText.Foreground = B(rt ? "GoodBrush" : "WarnBrush");
        ProtectionNote.Text = rt
            ? $"Watching {s.WatchedFolders.Count(Directory.Exists)} folders · {AppServices.Realtime.FilesChecked} files checked this session"
            : "Turn it on in Shield → Real-time";
        LastScanText.Text = s.LastScan is null ? "Never" : Ui.Ago(s.LastScan);

        VersionTile.Value = AppServices.Version;
        VersionTile.Note = AppServices.Manifest is { } m ? $"{m.Channel} · built {m.BuildDate}" : "Built from source";
        StatusTile.Note = AppServices.Manifest is null ? "No manifest, so file checks are skipped" : "Files verified by the launcher";
        if (AppServices.UpdateVersion is { } update)
        {
            StatusTile.Value = $"Update available ({update})";
            StatusTile.ValueBrush = B("AccentBrush");
            UpdateBanner.Visibility = Visibility.Visible;
            UpdateText.Text = $"VEYL {update} is available. Install it by running the new release's install.ps1.";
        }
        else
        {
            StatusTile.Value = AppServices.Manifest is null ? "Development build" : "Up to date";
            StatusTile.ValueBrush = B(AppServices.Manifest is null ? "InfoBrush" : "GoodBrush");
            UpdateBanner.Visibility = Visibility.Collapsed;
        }

        int sigs = Scanner.SignatureCount;
        SignatureTile.Value = $"{sigs:N0} hash{(sigs == 1 ? "" : "es")}";
        SignatureTile.Note = s.LastSignatureUpdate is null ? "Feeds never fetched" : $"Updated {Ui.Ago(s.LastSignatureUpdate)}";
        EngineTile.Value = $"Core {Core.Version}";
        EngineTile.Note = s.UseAmsi ? "Hashes · Heuristics · Defender AMSI" : "Hashes · Heuristics";

        var vault = AppServices.Vault;
        VaultTile.Value = !vault.Exists ? "Not set up" : vault.IsUnlocked ? $"Unlocked · {vault.Count} saved" : "Locked";
        VaultTile.ValueBrush = B(!vault.Exists ? "TextDimBrush" : vault.IsUnlocked ? "AccentBrush" : "TextBrush");
        VaultTile.Note = !vault.Exists ? "Create one under Vault → Passwords" : s.VaultAutoLockMinutes == 0 ? "Auto-lock off" : $"Locks after {s.VaultAutoLockMinutes} min idle";

        var quarantined = Quarantine.List(VeylPaths.QuarantineDir);
        int q = quarantined.Count;
        QuarantineTile.Value = q == 0 ? "Empty" : $"{q} item{(q == 1 ? "" : "s")}";
        QuarantineTile.Note = q == 0 ? "Nothing isolated" : $"Latest {Ui.Ago(quarantined[0].QuarantinedAt)}";
        QuarantineTile.ValueBrush = B(q == 0 ? "TextBrush" : "WarnBrush");

        var latest = ReleaseNotes.All.FirstOrDefault();
        if (latest is not null)
        {
            LatestVersion.Text = "v" + latest.Version;
            LatestDate.Text = DateTime.TryParse(latest.Date, out var d) ? d.ToString("MMM d") : latest.Date;
            LatestNotes.ItemsSource = latest.Notes;
        }
        RefreshActivity();
    }

    private void RefreshActivity()
    {
        RecentActivity.ItemsSource = AppServices.Activity.Items.Take(4).ToList();
        NoActivity.Visibility = AppServices.Activity.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void QuickScan_Click(object sender, RoutedEventArgs e)
    {
        MainWindow.Current?.Navigate("shield", "scan");
        _ = AppServices.Scan.RunAsync(ScanKind.Quick);
    }

    private void AllUpdates_Click(object sender, RoutedEventArgs e) => MainWindow.Current?.Navigate("home", "updates");
    private void AllActivity_Click(object sender, RoutedEventArgs e) => MainWindow.Current?.Navigate("home", "activity");
}
