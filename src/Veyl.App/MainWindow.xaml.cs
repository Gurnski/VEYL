using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Veyl.App.Services;
using Veyl.App.Views;
using Veyl.Shared;

namespace Veyl.App;

public sealed record PageDef(string Key, string Title, string Glyph, Func<FrameworkElement> Create);

public sealed record Workspace(string Key, string Title, string Subtitle, string Glyph, PageDef[] Pages);

public partial class MainWindow : Window
{
    public static MainWindow? Current { get; private set; }

    private readonly Workspace[] _workspaces =
    [
        new("home", "Home", "Status and activity", "",
        [
            new("overview", "Overview", "", () => new OverviewPage()),
            new("activity", "Activity", "", () => new ActivityPage()),
            new("updates", "Update Log", "", () => new UpdateLogPage()),
        ]),
        new("shield", "Shield", "Scan and protect this PC", "",
        [
            new("scan", "Scan", "", () => new ScanPage()),
            new("realtime", "Real-time", "", () => new ProtectionPage()),
            new("sandbox", "Sandbox", "", () => new SandboxPage()),
            new("quarantine", "Quarantine", "", () => new QuarantinePage()),
            new("signatures", "Signatures", "", () => new SignaturesPage()),
        ]),
        new("vault", "Vault", "Passwords and secrets", "",
        [
            new("passwords", "Passwords", "", () => new VaultPage()),
            new("generator", "Generator", "", () => new GeneratorPage()),
            new("vaultsettings", "Vault Settings", "", () => new VaultSettingsPage()),
        ]),
        new("settings", "Settings", "Customize VEYL", "",
        [
            new("general", "General", "", () => new SettingsPage()),
            new("about", "About", "", () => new AboutPage()),
        ]),
    ];

    private readonly Dictionary<string, FrameworkElement> _pages = [];
    private Workspace _workspace = null!;
    private bool _collapsed;

    public MainWindow()
    {
        InitializeComponent();
        Current = this;
        WindowHelper.ApplyDarkRounded(this);

        UserText.Text = VeylPaths.UserName;
        AvatarText.Text = VeylPaths.UserName[..1].ToUpperInvariant();
        BuildWorkspaceList();
        Navigate("home", "overview");

        AppServices.StateChanged += RefreshChips;
        RefreshChips();
        StateChanged += (_, _) =>
        {
            // A maximised borderless window overhangs the screen by the resize border.
            Root.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
            MaxButton.Content = WindowState == WindowState.Maximized ? "" : "";
        };
    }

    // ------------------------------------------------------------------ navigation

    public void Navigate(string workspaceKey, string? pageKey = null)
    {
        var ws = _workspaces.FirstOrDefault(w => w.Key == workspaceKey);
        if (ws is null) return;
        if (ws != _workspace)
        {
            _workspace = ws;
            WorkspaceTitle.Text = ws.Title;
            NavPanel.Children.Clear();
            foreach (var page in ws.Pages)
            {
                var item = new RadioButton
                {
                    Style = (Style)FindResource("NavItem"),
                    Content = page.Title,
                    Tag = page.Glyph,
                    GroupName = "nav",
                    ToolTip = page.Title,
                };
                item.Checked += (_, _) => ShowPage(page);
                NavPanel.Children.Add(item);
            }
            BuildWorkspaceList();
        }

        int index = Math.Max(0, Array.FindIndex(ws.Pages, p => p.Key == pageKey));
        var target = (RadioButton)NavPanel.Children[index];
        if (target.IsChecked == true) ShowPage(ws.Pages[index]);
        else target.IsChecked = true;
    }

    private void ShowPage(PageDef page)
    {
        string key = _workspace.Key + "/" + page.Key;
        if (!_pages.TryGetValue(key, out var view)) _pages[key] = view = page.Create();
        if (view is IRefreshable r) r.Refresh();
        PageHost.Content = view;

        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        PageHost.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
        PageShift.BeginAnimation(TranslateTransform.YProperty,
            new DoubleAnimation(10, 0, TimeSpan.FromMilliseconds(220)) { EasingFunction = ease });
    }

    private void BuildWorkspaceList()
    {
        WorkspaceList.Items.Clear();
        foreach (var ws in _workspaces)
        {
            bool current = ws == _workspace;
            var row = new Grid();
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition());
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var icon = new TextBlock { Text = ws.Glyph, Style = (Style)FindResource("Icon"), FontSize = 13, Margin = new(2, 2, 12, 0), VerticalAlignment = VerticalAlignment.Top, Foreground = (Brush)FindResource(current ? "AccentBrush" : "TextDimBrush") };
            var text = new StackPanel();
            text.Children.Add(new TextBlock { Text = ws.Title, Style = (Style)FindResource("SectionTitle") });
            text.Children.Add(new TextBlock { Text = ws.Subtitle, Style = (Style)FindResource("Faint") });
            Grid.SetColumn(text, 1);
            row.Children.Add(icon);
            row.Children.Add(text);
            if (current)
            {
                var check = new TextBlock { Text = "", Style = (Style)FindResource("Icon"), FontSize = 12 };
                Grid.SetColumn(check, 2);
                row.Children.Add(check);
            }

            var button = new Button
            {
                Content = row,
                Style = (Style)FindResource("GhostButton"),
                Padding = new(10, 8, 10, 8),
                HorizontalContentAlignment = HorizontalAlignment.Stretch,
                Foreground = (Brush)FindResource("TextBrush"),
            };
            // GhostButton centres content; stretch the row instead.
            row.Width = 210;
            button.Click += (_, _) =>
            {
                WorkspacePopup.IsOpen = false;
                Navigate(ws.Key);
            };
            WorkspaceList.Items.Add(button);
        }
    }

    // ------------------------------------------------------------------ elevated drag and drop

    // Windows blocks OLE drag-and-drop from Explorer into an elevated window. When VEYL
    // runs elevated (started by the sign-in task) we take the old WM_DROPFILES route
    // instead and let that one message through the integrity barrier.
    private const int WM_DROPFILES = 0x0233, WM_COPYDATA = 0x004A, WM_COPYGLOBALDATA = 0x0049;

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hwnd, int msg, int action, IntPtr info);
    [System.Runtime.InteropServices.DllImport("shell32.dll")]
    private static extern void DragAcceptFiles(IntPtr hwnd, bool accept);
    [System.Runtime.InteropServices.DllImport("shell32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern int DragQueryFile(IntPtr hDrop, int index, System.Text.StringBuilder? file, int size);
    [System.Runtime.InteropServices.DllImport("shell32.dll")]
    private static extern void DragFinish(IntPtr hDrop);
    [System.Runtime.InteropServices.DllImport("ole32.dll")]
    private static extern int RevokeDragDrop(IntPtr hwnd);

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        if (!AppServices.IsElevated) return;
        var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
        RevokeDragDrop(hwnd);  // otherwise Explorer tries OLE, which UIPI refuses
        foreach (int msg in new[] { WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA })
            ChangeWindowMessageFilterEx(hwnd, msg, 1 /* MSGFLT_ALLOW */, IntPtr.Zero);
        DragAcceptFiles(hwnd, true);
        System.Windows.Interop.HwndSource.FromHwnd(hwnd).AddHook(DropHook);
    }

    private IntPtr DropHook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg != WM_DROPFILES) return IntPtr.Zero;
        var paths = new List<string>();
        int count = DragQueryFile(wParam, -1, null, 0);
        for (int i = 0; i < count; i++)
        {
            var sb = new System.Text.StringBuilder(DragQueryFile(wParam, i, null, 0) + 1);
            DragQueryFile(wParam, i, sb, sb.Capacity);
            paths.Add(sb.ToString());
        }
        DragFinish(wParam);
        ScanPaths(paths);
        handled = true;
        return IntPtr.Zero;
    }

    /// <summary>Opens Shield → Sandbox and runs the file there.</summary>
    public void SandboxFile(string path)
    {
        Navigate("shield", "sandbox");
        if (_pages.TryGetValue("shield/sandbox", out var page) && page is SandboxPage sandbox) sandbox.RunFile(path);
    }

    /// <summary>Opens Shield → Scan and scans the given files and folders.</summary>
    public void ScanPaths(IReadOnlyList<string> paths)
    {
        // Dropped on the Sandbox page: run it there instead of scanning.
        if (PageHost.Content is SandboxPage sandbox && paths.Count > 0)
        {
            sandbox.RunFile(paths[0]);
            return;
        }
        Navigate("shield", "scan");
        if (_pages.TryGetValue("shield/scan", out var page) && page is ScanPage scan) scan.ScanDropped(paths);
    }

    // ------------------------------------------------------------------ status chips

    private void RefreshChips()
    {
        bool rt = AppServices.Realtime.IsActive;
        ShieldText.Text = rt ? "Protected" : "Real-time off";
        var shieldBrush = (Brush)FindResource(rt ? "GoodBrush" : "WarnBrush");
        ShieldIcon.Foreground = shieldBrush;
        ShieldText.Foreground = (Brush)FindResource("TextBrush");

        var vault = AppServices.Vault;
        VaultIcon.Text = vault.IsUnlocked ? "" : "";
        VaultIcon.Foreground = (Brush)FindResource(vault.IsUnlocked ? "AccentBrush" : "TextDimBrush");
        VaultText.Text = !vault.Exists ? "No vault" : vault.IsUnlocked ? $"{vault.Count} saved" : "Locked";

        AppServices.Tray?.SetStatus($"VEYL · {(rt ? "Protected" : "Real-time off")} · Vault {(vault.IsUnlocked ? "unlocked" : "locked")}");
    }

    // ------------------------------------------------------------------ overlay + toast

    public bool OverlayOpen => Overlay.Visibility == Visibility.Visible;

    public void ShowOverlay(FrameworkElement content)
    {
        OverlayHost.Content = content;
        Overlay.Visibility = Visibility.Visible;
        Overlay.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(150)));
    }

    public void CloseOverlay()
    {
        Overlay.Visibility = Visibility.Collapsed;
        OverlayHost.Content = null;
    }

    /// <summary>Shows an in-window confirmation card; returns true if confirmed.</summary>
    public Task<bool> ConfirmAsync(string title, string message, string confirmText, bool danger = false)
    {
        var tcs = new TaskCompletionSource<bool>();
        ShowOverlay(new ConfirmDialog(title, message, confirmText, danger, ok =>
        {
            CloseOverlay();
            tcs.TrySetResult(ok);
        }));
        return tcs.Task;
    }

    public void ShowToast(string message)
    {
        ToastText.Text = message;
        var fade = new DoubleAnimationUsingKeyFrames();
        fade.KeyFrames.Add(new EasingDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(150))));
        fade.KeyFrames.Add(new EasingDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(2400))));
        fade.KeyFrames.Add(new EasingDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(2800))));
        Toast.BeginAnimation(OpacityProperty, fade);
    }

    // ------------------------------------------------------------------ chrome handlers

    private void WorkspaceButton_Click(object sender, RoutedEventArgs e)
    {
        WorkspacePopup.IsOpen = !WorkspacePopup.IsOpen;
        ChevronRotate.BeginAnimation(RotateTransform.AngleProperty, new DoubleAnimation(WorkspacePopup.IsOpen ? 180 : 0, TimeSpan.FromMilliseconds(150)));
    }

    private void WorkspacePopup_Closed(object? sender, EventArgs e) =>
        ChevronRotate.BeginAnimation(RotateTransform.AngleProperty, new DoubleAnimation(0, TimeSpan.FromMilliseconds(150)));

    private void Collapse_Click(object sender, RoutedEventArgs e)
    {
        _collapsed = !_collapsed;
        SidebarColumn.Width = new GridLength(_collapsed ? 76 : 232);
        SidebarHeader.Visibility = _collapsed ? Visibility.Hidden : Visibility.Visible;
        SidebarArt.Visibility = _collapsed ? Visibility.Collapsed : Visibility.Visible;
        CollapseButton.Content = _collapsed ? "" : "";
        CollapseButton.ToolTip = _collapsed ? "Expand sidebar" : "Collapse sidebar";
    }

    private void ShieldChip_Click(object sender, RoutedEventArgs e) => Navigate("shield", "realtime");
    private void VaultChip_Click(object sender, RoutedEventArgs e) => Navigate("vault", "passwords");

    private void OpenDefender_Click(object sender, RoutedEventArgs e) =>
        Ui.OpenUnelevated("windowsdefender:");

    private void OpenData_Click(object sender, RoutedEventArgs e) =>
        Process.Start("explorer.exe", $"\"{VeylPaths.Root}\"");

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    protected override void OnClosing(CancelEventArgs e)
    {
        if (AppServices.Settings.CloseToTray)
        {
            e.Cancel = true;
            Hide();
            return;
        }
        base.OnClosing(e);
        ((App)Application.Current).ExitApp();
    }
}

/// <summary>Pages that need fresh data each time they're shown.</summary>
public interface IRefreshable
{
    void Refresh();
}
