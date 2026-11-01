using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

/// <summary>Shows a freshly made recovery key once, and won't close until the user confirms they kept it.</summary>
public partial class RecoveryKeyDialog : UserControl
{
    private char[] _key;
    private readonly Action _done;

    public RecoveryKeyDialog(char[] key, Action done)
    {
        InitializeComponent();
        _key = key;
        _done = done;
        // Two rows of four groups reads (and copies down by hand) more easily than one long line.
        string[] groups = new string(key).Split('-');
        KeyText.Text = string.Join("  ", groups[..4]) + "\n" + string.Join("  ", groups[4..]);
        KeyText.LineHeight = 34;
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Core.CopySecret(_key, 60);
            MainWindow.Current?.ShowToast("Recovery key copied · clears in 60s");
        }
        catch (VeylException)
        {
            MainWindow.Current?.ShowToast("Clipboard is busy, try again");
        }
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Title = "Save your recovery key (ideally to a USB stick)",
            FileName = $"VEYL recovery key - {VeylPaths.UserName}.txt",
            Filter = "Text file|*.txt",
        };
        if (dlg.ShowDialog() != true) return;
        File.WriteAllText(dlg.FileName,
            $"VEYL recovery key for {VeylPaths.UserName} on {Environment.MachineName}\r\n" +
            $"Created {DateTime.Now:d MMMM yyyy}\r\n\r\n" +
            $"    {new string(_key)}\r\n\r\n" +
            "If you forget your master password, open VEYL > Vault, choose\r\n" +
            "\"Forgot your master password?\" and enter this key.\r\n" +
            "Anyone with this key can open your vault. Keep it somewhere safe.\r\n");
        MainWindow.Current?.ShowToast("Saved");
    }

    private void Confirm_Changed(object sender, RoutedEventArgs e) => DoneButton.IsEnabled = Confirm.IsChecked == true;

    private void Done_Click(object sender, RoutedEventArgs e)
    {
        Array.Clear(_key);
        _key = [];
        KeyText.Text = "";
        _done();
    }

    /// <summary>Creates a recovery key for the open vault and shows it in the main window.</summary>
    public static void CreateAndShow(Action? afterwards = null)
    {
        var main = MainWindow.Current!;
        char[] key;
        try { key = AppServices.Vault.CreateRecoveryKey(); }
        catch (VeylException ex)
        {
            main.ShowToast("Couldn't create a recovery key: " + ex.Message);
            return;
        }
        afterwards?.Invoke();  // e.g. hide the "no recovery key" banner straight away
        main.ShowOverlay(new RecoveryKeyDialog(key, () =>
        {
            main.CloseOverlay();
            afterwards?.Invoke();
        }));
    }
}
