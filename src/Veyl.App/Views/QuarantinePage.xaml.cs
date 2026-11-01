using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

public sealed record QuarantineRow(QuarantineItem Item)
{
    public string Name => Path.GetFileName(Item.OriginalPath);
    public string When => Ui.Ago(Item.QuarantinedAt);
    public string Size => Ui.Size(Item.Size);
}

public partial class QuarantinePage : UserControl, IRefreshable
{
    public QuarantinePage() => InitializeComponent();

    public void Refresh()
    {
        var rows = Quarantine.List(VeylPaths.QuarantineDir).Select(i => new QuarantineRow(i)).ToList();
        Items.ItemsSource = rows;
        Empty.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private static QuarantineRow Row(object sender) => (QuarantineRow)((FrameworkElement)sender).DataContext;

    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        var row = Row(sender);
        var main = MainWindow.Current!;
        if (!await main.ConfirmAsync("Restore this file?",
                $"{row.Name} was flagged as {row.Item.Threat}. Only restore it if you're sure it's safe. " +
                "If real-time protection is on, a known-bad file will be caught again.", "Restore"))
            return;

        string? target = null;
        if (File.Exists(row.Item.OriginalPath))
        {
            var dlg = new SaveFileDialog { FileName = row.Name, Title = "The original location is taken. Restore to…" };
            if (dlg.ShowDialog() != true) return;
            target = dlg.FileName;
        }
        try
        {
            Quarantine.Restore(VeylPaths.QuarantineDir, row.Item.Id, target);
            AppServices.Activity.Add(LogKind.Quarantine, $"Restored {row.Name}", target ?? row.Item.OriginalPath);
            main.ShowToast($"Restored {row.Name}");
        }
        catch (VeylException ex)
        {
            await main.ConfirmAsync("Couldn't restore", ex.Status == VeylStatus.IoError
                ? "Windows refused to write the file there. Try restoring somewhere else, or run VEYL as administrator."
                : ex.Message, "OK");
        }
        Refresh();
        AppServices.Raise();
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        var row = Row(sender);
        if (!await MainWindow.Current!.ConfirmAsync("Delete permanently?", $"{row.Name} will be gone for good.", "Delete", danger: true))
            return;
        try
        {
            Quarantine.Delete(VeylPaths.QuarantineDir, row.Item.Id);
            AppServices.Activity.Add(LogKind.Quarantine, $"Deleted {row.Name}", row.Item.Threat);
        }
        catch (VeylException) { }
        Refresh();
        AppServices.Raise();
    }
}
