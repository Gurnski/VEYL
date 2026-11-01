using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

public partial class VaultSettingsPage : UserControl, IRefreshable
{
    private bool _loading;

    public VaultSettingsPage() => InitializeComponent();

    public void Refresh()
    {
        _loading = true;
        LockSlider.Value = AppServices.Settings.VaultAutoLockMinutes;
        ClipSlider.Value = AppServices.Settings.ClipboardClearSeconds;
        _loading = false;
        UpdateLabels();
        PathText.Text = VeylPaths.VaultFile;
        bool unlocked = AppServices.Vault.IsUnlocked;
        ChangeButton.IsEnabled = unlocked;
        bool hasKey = AppServices.Vault.HasRecoveryKey;
        RecoveryButton.IsEnabled = unlocked;
        RecoveryButton.Content = hasKey ? "Make a new key" : "Create recovery key";
        RecoveryStatus.Text = !unlocked ? "Unlock the vault to manage its recovery key"
            : hasKey ? "Recovery key is set up" : "No recovery key";
        RecoveryStatus.Foreground = (Brush)FindResource(!unlocked ? "TextDimBrush" : hasKey ? "GoodBrush" : "WarnBrush");
        RecoveryHint.Text = hasKey
            ? "Lost it, or think someone else saw it? Make a new one; the old key stops working straight away."
            : "Lets you get back in if you forget your master password.";
        ChangeHint.Text = unlocked
            ? "Re-encrypts the vault with a key from the new password."
            : "Unlock the vault first.";
    }

    private void UpdateLabels()
    {
        int m = (int)LockSlider.Value, c = (int)ClipSlider.Value;
        LockText.Text = m == 0 ? "Never" : $"{m} min";
        ClipText.Text = c == 0 ? "Never" : $"{c} sec";
    }

    private void Slider_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (_loading || !IsLoaded) return;
        UpdateLabels();
        AppServices.Settings.VaultAutoLockMinutes = (int)LockSlider.Value;
        AppServices.Settings.ClipboardClearSeconds = (int)ClipSlider.Value;
        AppServices.Settings.Save();
        AppServices.Vault.Touch();
    }

    private async void Recovery_Click(object sender, RoutedEventArgs e)
    {
        if (AppServices.Vault.HasRecoveryKey &&
            !await MainWindow.Current!.ConfirmAsync("Replace your recovery key?",
                "Your current recovery key will stop working as soon as the new one is made.", "Make new key"))
            return;
        RecoveryKeyDialog.CreateAndShow(Refresh);
    }

    private void Status(string text, bool error)
    {
        ChangeStatus.Text = text;
        ChangeStatus.Foreground = (Brush)FindResource(error ? "DangerBrush" : "GoodBrush");
    }

    private async void Change_Click(object sender, RoutedEventArgs e)
    {
        using var current = CurrentBox.SecurePassword;
        using var next = NewBox.SecurePassword;
        using var confirm = ConfirmBox.SecurePassword;
        if (current.Length == 0)
        {
            Status("Enter your current master password.", true);
            return;
        }
        if (next.Length < 8 || PasswordStrength.Measure(next).Level < Strength.Fair)
        {
            Status("Pick a longer or less predictable new password.", true);
            return;
        }
        if (!PasswordStrength.SecureEquals(next, confirm))
        {
            Status("The new passwords don't match.", true);
            return;
        }

        ChangeButton.IsEnabled = false;
        Status("Checking…", false);
        // Prove the current password by opening the file independently of the live session.
        var check = await Task.Run(() => VaultSession.Open(VeylPaths.VaultFile, current));
        if (check is null)
        {
            Status("Current password is wrong.", true);
            ChangeButton.IsEnabled = true;
            return;
        }
        check.Dispose();

        try
        {
            await Task.Run(() => AppServices.Vault.Session.ChangeMasterPassword(next));
            AppServices.Activity.Add(LogKind.Vault, "Master password changed");
            Status("Master password changed.", false);
            CurrentBox.Clear();
            NewBox.Clear();
            ConfirmBox.Clear();
        }
        catch (Exception ex) when (ex is VeylException or InvalidOperationException)
        {
            Status(ex.Message, true);
        }
        ChangeButton.IsEnabled = AppServices.Vault.IsUnlocked;
    }
}
