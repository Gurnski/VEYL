using System.Windows;
using System.Windows.Controls;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

public partial class GeneratorPage : UserControl, IRefreshable
{
    private char[] _current = [];
    private bool _loading;

    public GeneratorPage()
    {
        InitializeComponent();
        Unloaded += (_, _) => Wipe();
    }

    public void Refresh()
    {
        _loading = true;
        LengthSlider.Value = AppServices.Settings.GeneratorLength;
        SymbolToggle.IsChecked = AppServices.Settings.GeneratorSymbols;
        _loading = false;
        Generate();
    }

    private GenFlags Flags()
    {
        GenFlags f = 0;
        if (LowerToggle.IsChecked == true) f |= GenFlags.Lower;
        if (UpperToggle.IsChecked == true) f |= GenFlags.Upper;
        if (DigitToggle.IsChecked == true) f |= GenFlags.Digits;
        if (SymbolToggle.IsChecked == true) f |= GenFlags.Symbols;
        if (AmbiguousToggle.IsChecked == true) f |= GenFlags.NoAmbiguous;
        return f;
    }

    private void Generate()
    {
        if (Output is null) return;
        int length = (int)LengthSlider.Value;
        LengthText.Text = length.ToString();
        var flags = Flags();
        if ((flags & ~GenFlags.NoAmbiguous) == 0)
        {
            Output.Text = "";
            StrengthText.Text = "Pick at least one kind of character.";
            return;
        }
        Wipe();
        _current = Core.GeneratePassword(length, flags);
        Output.Text = new string(_current);
        var (level, bits) = PasswordStrength.Measure(_current);
        StrengthText.Text = $"{level} · about {bits:0} bits of entropy";
    }

    private void Wipe() => Array.Clear(_current);

    private void Option_Changed(object sender, RoutedEventArgs e)
    {
        // The slider fires while InitializeComponent applies its Minimum; don't save that.
        if (_loading || !IsLoaded) return;
        AppServices.Settings.GeneratorLength = (int)LengthSlider.Value;
        AppServices.Settings.GeneratorSymbols = SymbolToggle.IsChecked == true;
        AppServices.Settings.Save();
        Generate();
    }

    private void Regenerate_Click(object sender, RoutedEventArgs e) => Generate();

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        if (_current.Length == 0) return;
        int secs = AppServices.Settings.ClipboardClearSeconds;
        try
        {
            Core.CopySecret(_current, secs);
            MainWindow.Current?.ShowToast(secs > 0 ? $"Copied · clears in {secs}s" : "Copied");
        }
        catch (VeylException)
        {
            MainWindow.Current?.ShowToast("Clipboard is busy, try again");
        }
    }
}
