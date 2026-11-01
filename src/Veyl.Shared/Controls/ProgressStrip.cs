using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace Veyl.Shared.Controls;

/// <summary>Thin progress bar with a travelling shimmer, as used by the launcher and setup.</summary>
public sealed class ProgressStrip : Grid
{
    private readonly Border _fill;
    private readonly Border _shimmer;
    private readonly TranslateTransform _shift = new();
    private double _fraction;

    public ProgressStrip()
    {
        Height = 4;
        ClipToBounds = true;
        Children.Add(new Border { Background = new SolidColorBrush(Color.FromArgb(0x33, 0xFF, 0xFF, 0xFF)), CornerRadius = new(2) });
        _fill = new Border { CornerRadius = new(2), HorizontalAlignment = HorizontalAlignment.Left, Width = 0 };
        Children.Add(_fill);
        var glow = new LinearGradientBrush { StartPoint = new(0, 0), EndPoint = new(1, 0) };
        glow.GradientStops.Add(new(Color.FromArgb(0, 255, 255, 255), 0));
        glow.GradientStops.Add(new(Color.FromArgb(0x99, 255, 255, 255), 0.5));
        glow.GradientStops.Add(new(Color.FromArgb(0, 255, 255, 255), 1));
        _shimmer = new Border { Width = 90, CornerRadius = new(2), HorizontalAlignment = HorizontalAlignment.Left, Background = glow, RenderTransform = _shift };
        Children.Add(_shimmer);

        Loaded += (_, _) =>
        {
            _fill.Background ??= (Brush)FindResource("TextBrush");
            Busy = true;
        };
        SizeChanged += (_, _) => SetProgress(_fraction, animate: false);
    }

    /// <summary>Shows the travelling shimmer while work is in progress.</summary>
    public bool Busy
    {
        set
        {
            _shimmer.Visibility = value ? Visibility.Visible : Visibility.Collapsed;
            _shift.BeginAnimation(TranslateTransform.XProperty, value
                ? new DoubleAnimation(-90, Math.Max(ActualWidth, 300), TimeSpan.FromSeconds(1.6)) { RepeatBehavior = RepeatBehavior.Forever }
                : null);
        }
    }

    public Brush FillBrush { set => _fill.Background = value; }

    public void SetProgress(double fraction, bool animate = true)
    {
        _fraction = Math.Clamp(fraction, 0, 1);
        double target = ActualWidth * _fraction;
        _fill.BeginAnimation(WidthProperty, animate
            ? new DoubleAnimation(target, TimeSpan.FromMilliseconds(400)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } }
            : null);
        if (!animate) _fill.Width = target;
    }
}
