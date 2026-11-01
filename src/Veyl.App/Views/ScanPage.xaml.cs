using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using Microsoft.Win32;
using Veyl.App.Services;

namespace Veyl.App.Views;

public partial class ScanPage : UserControl, IRefreshable
{
    private readonly ScanService _scan = AppServices.Scan;
    private ScanKind _mode = ScanKind.Quick;
    private string? _dropped;  // name of what was last dropped, for the result title

    public ScanPage()
    {
        InitializeComponent();
        DetectionList.ItemsSource = _scan.Detections;
        _scan.PropertyChanged += OnScanChanged;
        _scan.Detections.CollectionChanged += (_, _) => UpdateDetections();
        Refresh();
    }

    public void Refresh()
    {
        UpdateHero();
        UpdateDetections();
    }

    private void OnScanChanged(object? sender, PropertyChangedEventArgs e)
    {
        FilesText.Text = _scan.FilesScanned.ToString("N0");
        ElapsedText.Text = string.IsNullOrEmpty(_scan.Elapsed) ? "00:00" : _scan.Elapsed;
        CurrentFile.Text = _scan.CurrentPath;
        if (e.PropertyName is nameof(ScanService.IsRunning) or nameof(ScanService.Summary) or nameof(ScanService.Kind))
            UpdateHero();
    }

    private void UpdateHero()
    {
        bool running = _scan.IsRunning;
        StartButton.Visibility = running ? Visibility.Collapsed : Visibility.Visible;
        StopButton.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        RunningPanel.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        ModeStrip.IsEnabled = !running;
        DeepToggle.Visibility = running ? Visibility.Collapsed : Visibility.Visible;

        if (running)
        {
            HeroTitle.Text = $"{_scan.Kind} scan in progress";
            HeroDetail.Text = "You can keep using your PC. Closing this window won't stop the scan.";
            HeroIcon.Text = "";
            HeroSpin.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty,
                new DoubleAnimation(0, 360, TimeSpan.FromSeconds(1.4)) { RepeatBehavior = RepeatBehavior.Forever });
            ScanSweep.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty,
                new DoubleAnimation(-140, Math.Max(400, ScanTrack.ActualWidth), TimeSpan.FromSeconds(1.5)) { RepeatBehavior = RepeatBehavior.Forever });
            return;
        }

        HeroSpin.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, null);
        ScanSweep.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty, null);
        HeroIcon.Text = "";

        if (!string.IsNullOrEmpty(_scan.Summary))
        {
            int open = _scan.Detections.Count(d => !d.IsResolved);
            HeroTitle.Text = open != 0 ? $"{open} item{(open == 1 ? "" : "s")} need attention"
                : _dropped is not null ? $"No threats in {_dropped}"
                : "No threats need attention";
            HeroDetail.Text = _scan.Summary;
            HeroIcon.Text = open == 0 ? "" : "";
            return;
        }

        HeroTitle.Text = _mode switch
        {
            ScanKind.Quick => "Quick scan",
            ScanKind.Full => "Full scan",
            _ => "Custom scan",
        };
        HeroDetail.Text = _mode switch
        {
            ScanKind.Quick => "Checks running programs, Downloads, Desktop, Startup and Temp. Usually takes a minute or two.",
            ScanKind.Full => $"Checks every file on {string.Join(", ", ScanService.FullScanRoots())}. Can take a long time on large drives.",
            _ => "Pick a folder to scan.",
        };
    }

    private void UpdateDetections()
    {
        NoDetections.Visibility = _scan.Detections.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ThreatsText.Text = _scan.Detections.Count.ToString();
        QuarantineAllButton.Visibility = !_scan.IsRunning && _scan.Detections.Count(d => !d.IsResolved) > 1
            ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Mode_Checked(object sender, RoutedEventArgs e)
    {
        _mode = sender == FullMode ? ScanKind.Full : sender == CustomMode ? ScanKind.Custom : ScanKind.Quick;
        if (HeroTitle is not null && !_scan.IsRunning) UpdateHero();
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        IReadOnlyList<string>? roots = null;
        if (_mode == ScanKind.Custom)
        {
            var dlg = new OpenFolderDialog { Title = "Choose folders to scan", Multiselect = true };
            if (dlg.ShowDialog() != true) return;
            roots = dlg.FolderNames;
        }
        _dropped = null;
        await _scan.RunAsync(_mode, roots, DeepToggle.IsChecked == true);
        UpdateDetections();
    }

    private void Stop_Click(object sender, RoutedEventArgs e) => _scan.Stop();

    // ------------------------------------------------------------ drag and drop

    private void Page_DragEnter(object sender, DragEventArgs e)
    {
        bool ok = e.Data.GetDataPresent(DataFormats.FileDrop) && !_scan.IsRunning;
        e.Effects = ok ? DragDropEffects.Copy : DragDropEffects.None;
        DropHint.Visibility = ok ? Visibility.Visible : Visibility.Collapsed;
        e.Handled = true;
    }

    private void Page_DragLeave(object sender, DragEventArgs e) => DropHint.Visibility = Visibility.Collapsed;

    private void Page_Drop(object sender, DragEventArgs e)
    {
        DropHint.Visibility = Visibility.Collapsed;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths) ScanDropped(paths);
    }

    /// <summary>Scans dropped files/folders. Also used by the main window's elevated-mode drop handler.</summary>
    public async void ScanDropped(IReadOnlyList<string> paths)
    {
        if (paths.Count == 0) return;
        if (_scan.IsRunning)
        {
            MainWindow.Current?.ShowToast("A scan is already running");
            return;
        }
        CustomMode.IsChecked = true;
        _dropped = DescribeDrop(paths);
        await _scan.RunAsync(ScanKind.Custom, paths, DeepToggle.IsChecked == true);
        UpdateDetections();
        UpdateHero();

        // A single file scans in a fraction of a second, so say so out loud.
        int open = _scan.Detections.Count(d => !d.IsResolved);
        MainWindow.Current?.ShowToast(open == 0
            ? $"No threats found in {_dropped}"
            : $"{open} threat{(open == 1 ? "" : "s")} found in {_dropped}");
        PulseHero();
    }

    private static string DescribeDrop(IReadOnlyList<string> paths)
    {
        if (paths.Count > 1) return $"{paths.Count} items";
        string name = Path.GetFileName(paths[0].TrimEnd('\\', '/'));
        return string.IsNullOrEmpty(name) ? paths[0] : name;  // a drive root has no file name
    }

    private void PulseHero()
    {
        var pulse = new DoubleAnimation(0.35, 1, TimeSpan.FromMilliseconds(450)) { EasingFunction = new QuadraticEase() };
        HeroCard.BeginAnimation(OpacityProperty, pulse);
    }

    private static Detection Item(object sender) => (Detection)((FrameworkElement)sender).DataContext;

    private void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        ScanService.QuarantineDetection(Item(sender));
        UpdateHero();
        UpdateDetections();
    }

    private void QuarantineAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var d in _scan.Detections.Where(d => !d.IsResolved).ToList()) ScanService.QuarantineDetection(d);
        UpdateHero();
        UpdateDetections();
    }

    private void Dismiss_Click(object sender, RoutedEventArgs e)
    {
        _scan.Detections.Remove(Item(sender));
        UpdateHero();
    }

    private void Reveal_Click(object sender, RoutedEventArgs e) => Ui.RevealInExplorer(Item(sender).Result.Path);
}
