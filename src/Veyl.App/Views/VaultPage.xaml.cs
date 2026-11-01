using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

public sealed class EntryRow(VaultEntry entry) : Observable
{
    private static readonly string[] Palette = ["#EBA640", "#A3D27A", "#45C8DA", "#C79BF2", "#F28B82", "#F2C94C", "#7FB3F5"];

    public VaultEntry Entry { get; } = entry;
    public string Initial => Entry.Title.Length > 0 ? Entry.Title[..1].ToUpperInvariant() : "?";
    public string UrlSuffix => string.IsNullOrWhiteSpace(Entry.Url) ? "" : "  ·  " + Entry.Url;

    public Brush AvatarBrush
    {
        get
        {
            int h = 0;
            foreach (char c in Entry.Title.ToLowerInvariant()) h = h * 31 + c;
            return (Brush)new BrushConverter().ConvertFromString(Palette[Math.Abs(h % Palette.Length)])!;
        }
    }

    private string _revealed = "";
    public string Revealed
    {
        get => _revealed;
        set { if (Set(ref _revealed, value)) Raise(nameof(IsRevealed)); }
    }
    public bool IsRevealed => _revealed.Length > 0;
}

public partial class VaultPage : UserControl, IRefreshable
{
    private readonly VaultService _vault = AppServices.Vault;
    private List<EntryRow> _rows = [];

    public VaultPage()
    {
        InitializeComponent();
        _vault.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(VaultService.IsUnlocked)) Refresh();
        };
        LockedFor.Text = $"Signed in as {VeylPaths.UserName}";
        IsVisibleChanged += (_, _) => FocusInput();
        PreviewKeyDown += OnShortcut;
    }

    private bool _recovering;

    public void Refresh()
    {
        bool locked = _vault.Exists && !_vault.IsUnlocked;
        if (!locked) _recovering = false;
        SetupPanel.Visibility = !_vault.Exists ? Visibility.Visible : Visibility.Collapsed;
        LockedPanel.Visibility = locked && !_recovering ? Visibility.Visible : Visibility.Collapsed;
        RecoverPanel.Visibility = locked && _recovering ? Visibility.Visible : Visibility.Collapsed;
        UnlockedPanel.Visibility = _vault.IsUnlocked ? Visibility.Visible : Visibility.Collapsed;
        NoRecoveryBanner.Visibility = _vault.IsUnlocked && !_vault.HasRecoveryKey ? Visibility.Visible : Visibility.Collapsed;
        if (_vault.IsUnlocked) RebuildList();
        else
        {
            _rows.Clear();
            EntryList.ItemsSource = null;
            SearchBox.Clear();
        }
        FocusInput();
    }

    private void FocusInput()
    {
        if (!IsVisible) return;
        Dispatcher.BeginInvoke(DispatcherPriority.Input, () =>
        {
            if (LockedPanel.IsVisible) Keyboard.Focus(UnlockBox);
            else if (RecoverPanel.IsVisible) Keyboard.Focus(RecoveryBox);
            else if (SetupPanel.IsVisible) Keyboard.Focus(NewMaster);
        });
    }

    /// <summary>Ctrl+F search, Ctrl+N add, Ctrl+L lock, Esc clears the search.</summary>
    private void OnShortcut(object sender, KeyEventArgs e)
    {
        if (!_vault.IsUnlocked || MainWindow.Current?.OverlayOpen == true) return;
        bool ctrl = Keyboard.Modifiers == ModifierKeys.Control;
        if (ctrl && e.Key == Key.F) { SearchBox.Focus(); SearchBox.SelectAll(); e.Handled = true; }
        else if (ctrl && e.Key == Key.N) { OpenEditor(null); e.Handled = true; }
        else if (ctrl && e.Key == Key.L) { _vault.Lock("locked by you"); e.Handled = true; }
        else if (e.Key == Key.Escape && SearchBox.Text.Length > 0) { SearchBox.Clear(); e.Handled = true; }
    }

    // ------------------------------------------------------------ recovery

    private void Forgot_Click(object sender, RoutedEventArgs e)
    {
        _recovering = true;
        RecoverError.Visibility = Visibility.Collapsed;
        Refresh();
    }

    private void BackToLock_Click(object sender, RoutedEventArgs e)
    {
        _recovering = false;
        RecoveryBox.Clear();
        ResetPw1.Clear();
        ResetPw2.Clear();
        Refresh();
    }

    private void Reset_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Reset_Click(sender, e);
    }

    private async void Reset_Click(object sender, RoutedEventArgs e)
    {
        void Fail(string message)
        {
            RecoverError.Text = message;
            RecoverError.Visibility = Visibility.Visible;
        }

        using var pw1 = ResetPw1.SecurePassword;
        using var pw2 = ResetPw2.SecurePassword;
        if (RecoveryBox.Text.Count(char.IsLetterOrDigit) != 32) { Fail("A recovery key is 32 letters and numbers (dashes are optional)."); return; }
        if (pw1.Length < 8 || PasswordStrength.Measure(pw1).Level < Strength.Fair) { Fail("Pick a longer or less predictable master password."); return; }
        if (!PasswordStrength.SecureEquals(pw1, pw2)) { Fail("The new passwords don't match."); return; }

        using var key = new System.Security.SecureString();
        foreach (char c in RecoveryBox.Text) key.AppendChar(c);
        ResetButton.IsEnabled = false;
        ResetButton.Content = "Checking…";
        bool ok;
        try { ok = await _vault.ResetWithRecoveryKeyAsync(key, pw1); }
        catch (VeylException ex) when (ex.Status == VeylStatus.BadState)
        {
            ok = false;
            Fail("This vault has no recovery key. Recovery keys can only be made while the vault is unlocked.");
            ResetButton.IsEnabled = true;
            ResetButton.Content = "Reset password";
            return;
        }
        ResetButton.IsEnabled = true;
        ResetButton.Content = "Reset password";
        if (!ok)
        {
            Fail("That recovery key doesn't match this vault.");
            return;
        }
        RecoveryBox.Clear();
        ResetPw1.Clear();
        ResetPw2.Clear();
        _recovering = false;
        var main = MainWindow.Current!;
        main.ShowToast("Master password reset");
        // The key has now been typed on this PC; offer to swap it for a fresh one.
        if (await main.ConfirmAsync("Make a new recovery key?",
                "Your old recovery key still works. If anyone else could have seen it, replace it now.", "New recovery key"))
            RecoveryKeyDialog.CreateAndShow(Refresh);
    }

    private void CreateRecovery_Click(object sender, RoutedEventArgs e) => RecoveryKeyDialog.CreateAndShow(Refresh);

    // ------------------------------------------------------------ setup

    private void NewMaster_Changed(object sender, RoutedEventArgs e)
    {
        var (level, bits) = PasswordStrength.Measure(NewMaster.SecurePassword);
        string brush = level switch
        {
            Strength.Weak => "DangerBrush",
            Strength.Fair => "WarnBrush",
            Strength.Strong => "GoodBrush",
            _ => "AccentBrush",
        };
        Border[] bars = [Bar1, Bar2, Bar3, Bar4];
        for (int i = 0; i < bars.Length; i++)
            bars[i].Background = (Brush)FindResource(i < (int)level ? brush : "RaisedBrush");
        StrengthText.Text = level == Strength.Empty ? "" : $"{level} · {bits:0} bits";
    }

    private void Create_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Create_Click(sender, e);
    }

    private void Create_Click(object sender, RoutedEventArgs e)
    {
        void Fail(string message)
        {
            SetupError.Text = message;
            SetupError.Visibility = Visibility.Visible;
        }

        using var a = NewMaster.SecurePassword;
        using var b = ConfirmMaster.SecurePassword;
        if (a.Length < 8) { Fail("Use at least 8 characters. A short sentence works well."); return; }
        if (PasswordStrength.Measure(a).Level < Strength.Fair) { Fail("That password is too easy to guess. Make it longer or mix in other characters."); return; }
        if (!PasswordStrength.SecureEquals(a, b)) { Fail("The two passwords don't match."); return; }

        try
        {
            _vault.Create(a);
            NewMaster.Clear();
            ConfirmMaster.Clear();
            SetupError.Visibility = Visibility.Collapsed;
            Refresh();
            RecoveryKeyDialog.CreateAndShow(Refresh);
        }
        catch (VeylException ex)
        {
            Fail($"Couldn't create the vault: {ex.Message}");
        }
    }

    // ------------------------------------------------------------ unlock

    private void Unlock_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Unlock_Click(sender, e);
    }

    private async void Unlock_Click(object sender, RoutedEventArgs e)
    {
        if (UnlockBox.SecurePassword.Length == 0) return;
        UnlockButton.IsEnabled = false;
        UnlockButton.Content = "Unlocking…";
        UnlockError.Visibility = Visibility.Collapsed;
        bool ok;
        using (var pw = UnlockBox.SecurePassword)
            ok = await _vault.UnlockAsync(pw);
        UnlockBox.Clear();
        UnlockButton.IsEnabled = true;
        UnlockButton.Content = "Unlock";
        if (!ok)
        {
            UnlockError.Text = "Wrong master password.";
            UnlockError.Visibility = Visibility.Visible;
            FocusInput();
        }
    }

    // ------------------------------------------------------------ list

    private void RebuildList()
    {
        _rows = _vault.Entries.Select(e => new EntryRow(e)).ToList();
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        string q = SearchBox.Text.Trim();
        var visible = q.Length == 0
            ? _rows
            : _rows.Where(r => r.Entry.Title.Contains(q, StringComparison.CurrentCultureIgnoreCase)
                            || r.Entry.Username.Contains(q, StringComparison.CurrentCultureIgnoreCase)
                            || r.Entry.Url.Contains(q, StringComparison.CurrentCultureIgnoreCase)).ToList();
        EntryList.ItemsSource = visible;
        CountText.Text = _rows.Count.ToString();
        EmptyState.Visibility = visible.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        EmptyTitle.Text = _rows.Count == 0 ? "No passwords yet" : "No matches";
        EmptyDetail.Text = _rows.Count == 0 ? "Click Add to save your first one." : "Try a different search.";
    }

    private void Search_Changed(object sender, TextChangedEventArgs e)
    {
        _vault.Touch();
        ApplyFilter();
    }

    private static EntryRow Row(object sender) => (EntryRow)((FrameworkElement)sender).DataContext;

    private void Add_Click(object sender, RoutedEventArgs e) => OpenEditor(null);
    private void Edit_Click(object sender, RoutedEventArgs e) => OpenEditor(Row(sender).Entry);

    private void OpenEditor(VaultEntry? entry)
    {
        var main = MainWindow.Current!;
        main.ShowOverlay(new EntryEditor(entry, saved =>
        {
            main.CloseOverlay();
            if (!saved) return;
            _vault.Reload();
            RebuildList();
            AppServices.Raise();
            main.ShowToast(entry is null ? "Saved" : "Updated");
        }));
    }

    private void CopyUser_Click(object sender, RoutedEventArgs e)
    {
        var row = Row(sender);
        if (row.Entry.Username.Length == 0) return;
        Clipboard.SetText(row.Entry.Username);
        _vault.Touch();
        MainWindow.Current?.ShowToast("Username copied");
    }

    private void EntryList_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        // Only when the double-click lands on a row, not on its buttons or empty space.
        if (e.OriginalSource is DependencyObject d && ItemsControl.ContainerFromElement(EntryList, d) is ListBoxItem { DataContext: EntryRow row }
            && FindParent<Button>(d) is null)
            CopyPassword(row);
    }

    private static T? FindParent<T>(DependencyObject? d) where T : DependencyObject
    {
        while (d is not null and not T) d = VisualTreeHelper.GetParent(d);
        return d as T;
    }

    private void CopyPassword_Click(object sender, RoutedEventArgs e) => CopyPassword(Row(sender));

    private void CopyPassword(EntryRow row)
    {
        int secs = AppServices.Settings.ClipboardClearSeconds;
        try
        {
            _vault.Session.CopyPassword(row.Entry.Id, secs);
            MainWindow.Current?.ShowToast(secs > 0 ? $"Password copied · clears in {secs}s" : "Password copied");
        }
        catch (VeylException)
        {
            MainWindow.Current?.ShowToast("Clipboard is busy, try again");
        }
    }

    private void Reveal_Click(object sender, RoutedEventArgs e)
    {
        var row = Row(sender);
        if (row.IsRevealed)
        {
            row.Revealed = "";
            return;
        }
        row.Revealed = _vault.Session.RevealPassword(row.Entry.Id);
        // Hide again automatically.
        var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        t.Tick += (_, _) =>
        {
            row.Revealed = "";
            t.Stop();
        };
        t.Start();
    }

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        string url = Row(sender).Entry.Url.Trim();
        if (url.Length == 0) return;
        if (!url.Contains("://")) url = "https://" + url;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
            Ui.OpenUnelevated(uri.AbsoluteUri);
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        var row = Row(sender);
        if (!await MainWindow.Current!.ConfirmAsync($"Delete {row.Entry.Title}?",
                "This removes the entry and its password from your vault. It can't be undone.", "Delete", danger: true))
            return;
        _vault.Session.Delete(row.Entry.Id);
        AppServices.Activity.Add(LogKind.Vault, $"Deleted {row.Entry.Title}");
        _vault.Reload();
        RebuildList();
        AppServices.Raise();
    }

    private void Lock_Click(object sender, RoutedEventArgs e) => _vault.Lock("locked by you");
}
