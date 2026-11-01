using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;

namespace Veyl.App.Controls;

internal static class Res
{
    public static Style Style(string key) => (Style)Application.Current.FindResource(key);
    public static Brush Brush(string key) => (Brush)Application.Current.FindResource(key);
}

/// <summary>Overview-style card: small label over a bold value, optionally right-aligned.</summary>
public sealed class StatTile : Border
{
    private readonly TextBlock _label = new() { Style = Res.Style("Label") };
    private readonly TextBlock _value = new() { Style = Res.Style("Value") };
    private readonly TextBlock _note = new() { Style = Res.Style("Faint"), Margin = new(0, 3, 0, 0), Visibility = Visibility.Collapsed };

    public StatTile()
    {
        Style = Res.Style("Card");
        var stack = new StackPanel();
        stack.Children.Add(_label);
        stack.Children.Add(_value);
        stack.Children.Add(_note);
        Child = stack;
    }

    public string Label { get => _label.Text; set => _label.Text = value; }
    public string Value { get => _value.Text; set => _value.Text = value; }

    public string Note
    {
        get => _note.Text;
        set
        {
            _note.Text = value;
            _note.Visibility = string.IsNullOrEmpty(value) ? Visibility.Collapsed : Visibility.Visible;
        }
    }

    public Brush ValueBrush { get => _value.Foreground; set => _value.Foreground = value; }

    public bool AlignRight
    {
        set
        {
            var a = value ? HorizontalAlignment.Right : HorizontalAlignment.Left;
            _label.HorizontalAlignment = _value.HorizontalAlignment = _note.HorizontalAlignment = a;
        }
    }
}

/// <summary>Settings line: title + description on the left, any control on the right.</summary>
[ContentProperty(nameof(Control))]
public sealed class SettingRow : Border
{
    private readonly TextBlock _title = new() { Style = Res.Style("SectionTitle") };
    private readonly TextBlock _desc = new() { Style = Res.Style("Label"), TextWrapping = TextWrapping.Wrap, Margin = new(0, 3, 24, 0) };
    private readonly ContentControl _right = new() { VerticalAlignment = VerticalAlignment.Center, Focusable = false };

    public SettingRow()
    {
        Style = Res.Style("Card");
        Margin = new(0, 0, 0, 8);
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var text = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        text.Children.Add(_title);
        text.Children.Add(_desc);
        Grid.SetColumn(_right, 1);
        grid.Children.Add(text);
        grid.Children.Add(_right);
        Child = grid;
    }

    public string Title { get => _title.Text; set => _title.Text = value; }
    public string Description { get => _desc.Text; set => _desc.Text = value; }
    public object Control { get => _right.Content; set => _right.Content = value; }
}
