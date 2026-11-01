using System.Windows;
using System.Windows.Controls;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

/// <summary>Add/edit form for a vault entry, shown in the main window overlay.</summary>
public partial class EntryEditor : UserControl
{
    private readonly VaultEntry? _entry;
    private readonly Action<bool> _done;

    public EntryEditor(VaultEntry? entry, Action<bool> done)
    {
        InitializeComponent();
        _entry = entry;
        _done = done;
        Heading.Text = entry is null ? "Add password" : $"Edit {entry.Title}";
        if (entry is not null)
        {
            TitleBox.Text = entry.Title;
            UserBox.Text = entry.Username;
            UrlBox.Text = entry.Url;
            NotesBox.Text = entry.Notes;
            PassHint.Text = "Leave blank to keep the current password.";
        }
        Loaded += (_, _) => TitleBox.Focus();
    }

    private void Pass_Changed(object sender, RoutedEventArgs e)
    {
        AppServices.Vault.Touch();
        if (PassBox.SecurePassword.Length == 0)
        {
            PassHint.Text = _entry is null ? "" : "Leave blank to keep the current password.";
            return;
        }
        var (level, bits) = PasswordStrength.Measure(PassBox.SecurePassword);
        PassHint.Text = $"{level} · about {bits:0} bits";
    }

    private void Generate_Click(object sender, RoutedEventArgs e)
    {
        var s = AppServices.Settings;
        var flags = GenFlags.Lower | GenFlags.Upper | GenFlags.Digits | GenFlags.NoAmbiguous;
        if (s.GeneratorSymbols) flags |= GenFlags.Symbols;
        char[] pw = Core.GeneratePassword(s.GeneratorLength, flags);
        // PasswordBox has no char[] setter; this makes one short-lived managed string.
        PassBox.Password = new string(pw);
        Array.Clear(pw);
        PassHint.Text = $"Generated {s.GeneratorLength} characters. Change the defaults in Vault → Generator.";
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        string title = TitleBox.Text.Trim();
        if (title.Length == 0)
        {
            Error.Text = "Give it a name.";
            Error.Visibility = Visibility.Visible;
            return;
        }
        try
        {
            var session = AppServices.Vault.Session;
            using var pw = PassBox.SecurePassword;
            if (_entry is null)
            {
                session.Add(title, UserBox.Text.Trim(), pw, UrlBox.Text.Trim(), NotesBox.Text);
                AppServices.Activity.Add(LogKind.Vault, $"Added {title}");
            }
            else
            {
                session.Update(_entry.Id, title, UserBox.Text.Trim(), pw.Length > 0 ? pw : null, UrlBox.Text.Trim(), NotesBox.Text);
                AppServices.Activity.Add(LogKind.Vault, $"Updated {title}");
            }
            PassBox.Clear();
            _done(true);
        }
        catch (Exception ex) when (ex is VeylException or InvalidOperationException)
        {
            Error.Text = ex is InvalidOperationException ? "The vault locked itself. Unlock it and try again." : ex.Message;
            Error.Visibility = Visibility.Visible;
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        PassBox.Clear();
        _done(false);
    }
}
