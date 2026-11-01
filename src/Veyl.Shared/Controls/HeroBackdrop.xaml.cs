using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace Veyl.Shared.Controls;

public partial class HeroBackdrop : UserControl
{
    private readonly Random _rng = new();

    public HeroBackdrop()
    {
        InitializeComponent();
        Loaded += (_, _) => Start();
    }

    public string Tagline { get => TaglineText.Text; set => TaglineText.Text = value; }

    /// <summary>How far the logo sits above centre, to leave room for the panel below it.</summary>
    public double BrandLift { get => -Brand.Margin.Top; set => Brand.Margin = new Thickness(0, -value, 0, 0); }

    private void Start()
    {
        Drift(AmberShift, 30, 9);
        Drift(VioletShift, -40, 13);
        for (int i = 0; i < 26; i++) SpawnEmber(initial: true);
    }

    private static void Drift(TranslateTransform t, double dx, double seconds)
    {
        t.BeginAnimation(TranslateTransform.XProperty, new DoubleAnimation(0, dx, TimeSpan.FromSeconds(seconds))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
        });
        t.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(0, dx / 2, TimeSpan.FromSeconds(seconds * 0.7))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
        });
    }

    private void SpawnEmber(bool initial)
    {
        double w = ActualWidth > 0 ? ActualWidth : 720, h = ActualHeight > 0 ? ActualHeight : 420;
        double size = 1.5 + _rng.NextDouble() * 2.5;
        var dot = new Ellipse
        {
            Width = size,
            Height = size,
            Fill = new SolidColorBrush(Color.FromArgb((byte)_rng.Next(90, 200), 0xEB, 0xA6, 0x40)),
        };
        double x = _rng.NextDouble() * w;
        double startY = initial ? _rng.NextDouble() * h : h + 10;
        Canvas.SetLeft(dot, x);
        Canvas.SetTop(dot, startY);
        Embers.Children.Add(dot);

        var duration = TimeSpan.FromSeconds(6 + _rng.NextDouble() * 8);
        var rise = new DoubleAnimation(startY, -10, duration);
        rise.Completed += (_, _) =>
        {
            Embers.Children.Remove(dot);
            SpawnEmber(initial: false);
        };
        dot.BeginAnimation(Canvas.TopProperty, rise);
        dot.BeginAnimation(Canvas.LeftProperty, new DoubleAnimation(x, x + _rng.Next(-40, 40), duration));
    }
}
