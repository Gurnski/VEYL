using System.Windows;
using System.Windows.Controls;
using Veyl.App.Controls;

namespace Veyl.App.Views;

/// <summary>Small modal card shown in the main window's overlay.</summary>
public sealed class ConfirmDialog : Border
{
    public ConfirmDialog(string title, string message, string confirmText, bool danger, Action<bool> done)
    {
        Style = Res.Style("Card");
        Width = 420;
        Padding = new(22, 20, 22, 20);
        CornerRadius = new(12);

        var stack = new StackPanel();
        stack.Children.Add(new TextBlock { Text = title, Style = Res.Style("H2") });
        stack.Children.Add(new TextBlock
        {
            Text = message,
            Style = Res.Style("Dim"),
            TextWrapping = TextWrapping.Wrap,
            TextTrimming = TextTrimming.None,
            Margin = new(0, 8, 0, 20),
        });

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        var ok = new Button
        {
            Content = confirmText,
            Style = Res.Style(danger ? "DangerButton" : "PrimaryButton"),
            Margin = new(8, 0, 0, 0),
            IsDefault = true,
        };
        cancel.Click += (_, _) => done(false);
        ok.Click += (_, _) => done(true);
        buttons.Children.Add(cancel);
        buttons.Children.Add(ok);
        stack.Children.Add(buttons);
        Child = stack;
        Loaded += (_, _) => ok.Focus();
    }
}
