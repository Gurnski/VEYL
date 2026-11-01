using System.Collections.Specialized;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Microsoft.Win32;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

public partial class SandboxPage : UserControl, IRefreshable
{
    private static readonly string[] Categories = ["All", "Files", "Registry", "Processes", "Network"];
    private readonly SandboxService _sandbox = AppServices.Sandbox;
    private SandboxRun? _shown;
    private string _filter = "All";
    private readonly Dictionary<RadioButton, string> _filterButtons = [];

    public SandboxPage()
    {
        InitializeComponent();
        Promises.ItemsSource = new[]
        {
            Tuple.Create("", "Your files and settings stay untouched",
                "Anything it writes, changes or deletes happens to throwaway copies. Windows itself stops it changing the real ones."),
            Tuple.Create("", "No internet, clipboard or other windows",
                "It can't phone home, read what you copied (like passwords), or poke at other programs."),
            Tuple.Create("", "You see everything it tries",
                "Files, registry, programs it starts, network attempts and code injection, live, with a plain-English verdict."),
        };
        RunTabs.ItemsSource = _sandbox.Runs;
        foreach (string c in Categories)
        {
            var b = new RadioButton { Style = (Style)FindResource("TabItemButton"), GroupName = "sbxfilter", Tag = Glyph(c), Content = c, IsChecked = c == "All" };
            b.Checked += (_, _) =>
            {
                _filter = c;
                ApplyFilter();
            };
            Filters.Children.Add(b);
            _filterButtons[b] = c;
        }
        _sandbox.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(SandboxService.Current)) Show(_sandbox.Current);
        };
        _sandbox.Runs.CollectionChanged += (_, _) => RunTabs.Visibility = _sandbox.Runs.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
    }

    private static string Glyph(string category) => category switch
    {
        "Files" => "",
        "Registry" => "",
        "Processes" => "",
        "Network" => "",
        _ => "",
    };

    public void Refresh()
    {
        RunTabs.Visibility = _sandbox.Runs.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
        Show(_sandbox.Current);
    }

    // ------------------------------------------------------------ showing a run

    private void Show(SandboxRun? run)
    {
        if (_shown is not null)
        {
            _shown.PropertyChanged -= OnRunChanged;
            _shown.Events.CollectionChanged -= OnEvents;
            _shown.Findings.CollectionChanged -= OnFindings;
        }
        _shown = run;
        Intro.Visibility = run is null ? Visibility.Visible : Visibility.Collapsed;
        RunView.Visibility = run is null ? Visibility.Collapsed : Visibility.Visible;
        if (run is null) return;

        run.PropertyChanged += OnRunChanged;
        run.Events.CollectionChanged += OnEvents;
        run.Findings.CollectionChanged += OnFindings;
        RunName.Text = run.Name;
        RunPath.Text = run.ExePath;
        FindingList.ItemsSource = run.Findings;
        UpdateStatus();
        ApplyFilter();
    }

    private void OnRunChanged(object? sender, PropertyChangedEventArgs e) => UpdateStatus();
    private void OnFindings(object? sender, NotifyCollectionChangedEventArgs e) => UpdateStatus();

    private void OnEvents(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.NewItems is null || _shown is null) return;
        foreach (SandboxEvent ev in e.NewItems)
            if (_filter == "All" || ev.Category == _filter) ((List<SandboxEvent>)EventList.ItemsSource).Add(ev);
        EventList.Items.Refresh();
        UpdateCounts();
        NoEvents.Visibility = EventList.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ApplyFilter()
    {
        if (_shown is null) return;
        EventList.ItemsSource = _shown.Events.Where(e => _filter == "All" || e.Category == _filter).ToList();
        UpdateCounts();
        NoEvents.Text = _shown.IsRunning ? "Waiting for the program to do something…" : "Nothing recorded here.";
        NoEvents.Visibility = EventList.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateCounts()
    {
        if (_shown is null) return;
        foreach (var (b, c) in _filterButtons)
        {
            int n = c == "All" ? _shown.Events.Count : _shown.Events.Count(e => e.Category == c);
            b.Content = n > 0 ? $"{c}  {n}" : c;
        }
    }

    private Brush B(string key) => (Brush)FindResource(key);

    private void UpdateStatus()
    {
        var run = _shown;
        if (run is null) return;
        bool running = run.IsRunning;
        StopButton.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        AgainButton.Visibility = running ? Visibility.Collapsed : Visibility.Visible;
        VerdictActions.Visibility = running || run.Score < 35 ? Visibility.Collapsed : Visibility.Visible;

        (string text, string fg, string bg, string icon) = run.State switch
        {
            SandboxState.Running => ("RUNNING", "GoodBrush", "GoodSoftBrush", ""),
            SandboxState.Finished => ("FINISHED", "TextDimBrush", "RaisedBrush", ""),
            SandboxState.Stopped => ("STOPPED", "WarnBrush", "WarnSoftBrush", ""),
            SandboxState.TimedOut => ("TIME LIMIT", "WarnBrush", "WarnSoftBrush", ""),
            _ => ("FAILED", "DangerBrush", "DangerSoftBrush", ""),
        };
        StateText.Text = text;
        StateText.Foreground = B(fg);
        StateBadge.Background = B(bg);
        StateIcon.Text = icon;
        StateRing.BeginAnimation(OpacityProperty, running
            ? new DoubleAnimation(1, 0.45, TimeSpan.FromSeconds(0.9)) { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever }
            : null);

        string procs = running ? $" · {run.Processes} process{(run.Processes == 1 ? "" : "es")} running" : "";
        string limit = running ? $" · stops itself after {SandboxService.TimeLimit.TotalMinutes:0} min" : "";
        RunStats.Text = $"{run.Elapsed}{procs}{limit}{(run.ExitInfo.Length > 0 && !running ? " · " + run.ExitInfo : "")} · {run.Events.Count} actions recorded";

        VerdictText.Text = running && run.Score < 35 ? "Watching… nothing harmful so far" : run.Verdict;
        string brush = run.Score >= 70 ? "DangerBrush" : run.Score >= 35 ? "WarnBrush" : "GoodBrush";
        VerdictText.Foreground = B(brush);
        ScoreBar.Background = B(brush);
        double width = ((FrameworkElement)ScoreBar.Parent).ActualWidth;
        ScoreBar.BeginAnimation(WidthProperty, new DoubleAnimation(Math.Max(6, width * run.Score / 100.0), TimeSpan.FromMilliseconds(300)));
    }

    // ------------------------------------------------------------ actions

    public void RunFile(string path)
    {
        try
        {
            _sandbox.Start(path, "", NetToggle.IsChecked == true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or VeylException)
        {
            _ = MainWindow.Current!.ConfirmAsync("Couldn't start the sandbox", ex.Message, "OK");
        }
    }

    private void Run_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Choose a program to run in the sandbox",
            Filter = "Programs and scripts|*.exe;*.com;*.scr;*.bat;*.cmd;*.ps1;*.vbs;*.js;*.wsf|All files|*.*",
        };
        if (dlg.ShowDialog() == true) RunFile(dlg.FileName);
    }

    private void RunTab_Click(object sender, RoutedEventArgs e) =>
        _sandbox.Current = (SandboxRun)((FrameworkElement)sender).DataContext;

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (_shown is not null) _sandbox.Stop(_shown);
    }

    private void Again_Click(object sender, RoutedEventArgs e)
    {
        if (_shown is not null) RunFile(_shown.ExePath);
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_shown is not null && Directory.Exists(_shown.Root)) System.Diagnostics.Process.Start("explorer.exe", $"\"{_shown.Root}\"");
    }

    private async void Discard_Click(object sender, RoutedEventArgs e)
    {
        if (_shown is null) return;
        if (!await MainWindow.Current!.ConfirmAsync("Discard this run?",
                "Everything the program wrote in the sandbox is deleted, along with this report.", "Discard", danger: true))
            return;
        _sandbox.Discard(_shown);
    }

    private void Block_Click(object sender, RoutedEventArgs e)
    {
        if (_shown is null) return;
        string hash = Core.Sha256File(_shown.ExePath);
        int n = SignatureUpdater.Merge(new Dictionary<string, string> { [hash] = $"Sandbox:{_shown.Verdict.Replace(' ', '-')}" });
        AppServices.ReloadSignatures();
        AppServices.Activity.Add(LogKind.System, $"Blocked {_shown.Name}", "Added its hash after a sandbox run");
        MainWindow.Current?.ShowToast(n == 0 ? "Already blocked" : $"{_shown.Name} is now blocked");
    }

    private async void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if (_shown is null) return;
        try
        {
            Quarantine.Add(_shown.ExePath, VeylPaths.QuarantineDir, $"Sandbox:{_shown.Verdict}");
            AppServices.Activity.Add(LogKind.Quarantine, $"Quarantined {_shown.Name}", "After a sandbox run");
            AppServices.Raise();
            MainWindow.Current?.ShowToast($"{_shown.Name} moved to quarantine");
        }
        catch (VeylException)
        {
            await MainWindow.Current!.ConfirmAsync("Couldn't quarantine it", "The file is in use or VEYL doesn't have permission.", "OK");
        }
    }

    // ------------------------------------------------------------ drag and drop

    private void Page_DragEnter(object sender, DragEventArgs e)
    {
        bool ok = e.Data.GetDataPresent(DataFormats.FileDrop);
        e.Effects = ok ? DragDropEffects.Copy : DragDropEffects.None;
        DropHint.Visibility = ok ? Visibility.Visible : Visibility.Collapsed;
        e.Handled = true;
    }

    private void Page_DragLeave(object sender, DragEventArgs e) => DropHint.Visibility = Visibility.Collapsed;

    private void Page_Drop(object sender, DragEventArgs e)
    {
        DropHint.Visibility = Visibility.Collapsed;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths) RunFile(paths[0]);
    }
}
