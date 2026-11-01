using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

public sealed record PackRow(SignaturePack Pack)
{
    public string Count => $"{Pack.Hashes:N0} hash{(Pack.Hashes == 1 ? "" : "es")}";
    public string When => $"updated {Ui.Ago(Pack.Created)}";
    public string Size
    {
        get
        {
            try { return Ui.Size(new FileInfo(Pack.Path).Length); }
            catch (IOException) { return "?"; }
        }
    }
}

public partial class SignaturesPage : UserControl, IRefreshable
{
    public SignaturesPage() => InitializeComponent();

    public void Refresh()
    {
        var (md5, sha1, sha256) = Scanner.SignatureCounts;
        CountTile.Value = (md5 + sha1 + sha256).ToString("N0");
        var kinds = new[] { (md5, "MD5"), (sha1, "SHA-1"), (sha256, "SHA-256") }
            .Where(k => k.Item1 > 0).Select(k => $"{k.Item1:N0} {k.Item2}").ToList();
        CountTile.Note = kinds.Count > 0 ? string.Join("  ·  ", kinds) : "None yet";
        var packs = Scanner.Packs.Select(p => new PackRow(p)).ToList();
        PackList.ItemsSource = packs;
        NoPacks.Visibility = packs.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        UpdatedTile.Value = Ui.Ago(AppServices.Settings.LastSignatureUpdate);
        var feeds = AppServices.Settings.SignatureFeeds;
        UpdatedTile.Note = $"{feeds.Count + (AppServices.Manifest?.SignatureFeeds.Count ?? 0)} feed(s) configured";
        FeedsBox.Text = string.Join(Environment.NewLine, feeds);
    }

    private void Status(TextBlock target, string text)
    {
        target.Text = text;
        target.Visibility = Visibility.Visible;
    }

    private void Added(int count, string source)
    {
        AppServices.ReloadSignatures();
        if (count > 0) AppServices.Activity.Add(LogKind.System, $"Added {count:N0} signature{(count == 1 ? "" : "s")}", source);
        Refresh();
    }

    private void AddHash_Click(object sender, RoutedEventArgs e)
    {
        var parsed = SignatureUpdater.Parse([$"{HashBox.Text.Trim()} {NameBox.Text.Trim()}"], "Blocklisted file");
        if (parsed.Count == 0)
        {
            Status(AddStatus, "That isn't a hash VEYL can use. Paste an MD5 (32 characters), SHA-1 (40) or SHA-256 (64), using 0-9 and a-f.");
            return;
        }
        int n = SignatureUpdater.Merge(parsed);
        Status(AddStatus, n == 0 ? "That hash is already on the list." : "Added.");
        HashBox.Clear();
        NameBox.Clear();
        Added(n, "manual entry");
    }

    private void BlockFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Block a file by its hash" };
        if (dlg.ShowDialog() != true) return;
        string hash = Core.Sha256File(dlg.FileName);
        int n = SignatureUpdater.Merge(new Dictionary<string, string> { [hash] = $"User-blocked:{Path.GetFileName(dlg.FileName)}" });
        Status(AddStatus, n == 0 ? "That file is already blocked." : $"Blocked {Path.GetFileName(dlg.FileName)} ({hash[..12]}…).");
        Added(n, dlg.FileName);
    }

    // Imports go into a pack, never hashes.txt: VirusShare alone is tens of millions of hashes.
    private async void Import_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Import hash lists (you can select many files at once)",
            Multiselect = true,
            Filter = "Hash lists|*.txt;*.csv;*.md5;*.sha1;*.sha256|All files|*.*",
        };
        if (dlg.ShowDialog() != true) return;
        string[] files = dlg.FileNames;
        string label = SignatureUpdater.PackLabelFor(files);
        var existing = Scanner.Packs.FirstOrDefault(p => p.Label.Equals(label, StringComparison.OrdinalIgnoreCase));
        List<string> inputs = existing is null ? [.. files] : [existing.Path, .. files];
        long before = existing?.Hashes ?? 0;

        ImportButton.IsEnabled = false;
        Status(AddStatus, files.Length == 1 ? $"Importing {Path.GetFileName(files[0])}…" : $"Importing {files.Length:N0} files…");
        try
        {
            var (_, total) = await Task.Run(() => Scanner.CompilePack(inputs, label, VeylPaths.SignatureDir));
            long added = total - before;
            Status(AddStatus, $"Added {added:N0} new hash{(added == 1 ? "" : "es")} to the {label} pack ({total:N0} in all).");
            Added((int)Math.Min(added, int.MaxValue), files.Length == 1 ? files[0] : $"{files.Length:N0} files into {label}");
        }
        catch (VeylException ex)
        {
            Status(AddStatus, ex.Status == VeylStatus.BadFormat
                ? "Those files don't contain any MD5, SHA-1 or SHA-256 hashes."
                : $"The import failed: {ex.Message}.");
        }
        finally
        {
            ImportButton.IsEnabled = true;
        }
    }

    private async void RemovePack_Click(object sender, RoutedEventArgs e)
    {
        var pack = ((PackRow)((FrameworkElement)sender).DataContext).Pack;
        if (!await MainWindow.Current!.ConfirmAsync($"Remove the {pack.Label} pack?",
                $"VEYL will stop checking files against its {pack.Hashes:N0} hashes. You can import the lists again later.",
                "Remove", danger: true))
            return;
        try
        {
            Scanner.RemovePack(pack.Path);
            AppServices.Activity.Add(LogKind.System, $"Removed the {pack.Label} signature pack", $"{pack.Hashes:N0} hashes");
        }
        catch (VeylException)
        {
            Status(AddStatus, $"VEYL stopped using the {pack.Label} pack but couldn't delete {pack.Path}. It'll come back on the next start.");
        }
        AppServices.Raise();
        Refresh();
    }

    private void OpenFile_Click(object sender, RoutedEventArgs e) =>
        Process.Start(new ProcessStartInfo("notepad.exe", $"\"{VeylPaths.SignatureFile}\""));

    private void Feeds_LostFocus(object sender, RoutedEventArgs e)
    {
        AppServices.Settings.SignatureFeeds = FeedsBox.Text
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct().ToList();
        AppServices.Settings.Save();
    }

    private async void Update_Click(object sender, RoutedEventArgs e)
    {
        Feeds_LostFocus(sender, e);
        var feeds = (AppServices.Manifest?.SignatureFeeds ?? []).Concat(AppServices.Settings.SignatureFeeds).Distinct().ToList();
        if (feeds.Count == 0)
        {
            Status(FeedStatus, "Add a feed above first.");
            return;
        }
        UpdateButton.IsEnabled = false;
        Status(FeedStatus, "Fetching…");
        int n = await SignatureUpdater.UpdateFromFeedsAsync(feeds);
        AppServices.Settings.LastSignatureUpdate = DateTimeOffset.Now;
        AppServices.Settings.Save();
        Status(FeedStatus, $"Done. {n:N0} new hash{(n == 1 ? "" : "es")}.");
        UpdateButton.IsEnabled = true;
        Added(n, "feed update");
    }
}
