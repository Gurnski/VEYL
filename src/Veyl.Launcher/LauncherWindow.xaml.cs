using System.Reflection;
using System.Windows;
using System.Windows.Media;
using Veyl.Shared;

namespace Veyl.Launcher;

public partial class LauncherWindow : Window
{
    public LauncherWindow()
    {
        InitializeComponent();
        WindowHelper.ApplyDarkRounded(this);
        VersionText.Text = "v" + Assembly.GetExecutingAssembly().GetName().Version!.ToString(3);
        Loaded += async (_, _) => await RunAsync();
    }

    private async Task RunAsync()
    {
        ErrorActions.Visibility = Visibility.Collapsed;
        Progress.FillBrush = (Brush)FindResource("TextBrush");
        Progress.Busy = true;

        var result = await new LaunchSequence().RunAsync(step => Dispatcher.Invoke(() => ShowStep(step)));
        if (!result.Ok)
        {
            ShowError(result);
            return;
        }

        bool started = await Task.Run(() => LaunchSequence.StartApp(tray: false, result.UpdateVersion));
        if (!started)
        {
            ShowError(new(false, "VEYL didn't start", "The main program didn't respond. Check that Veyl.App.exe isn't being blocked."));
            return;
        }
        Progress.SetProgress(1);
        await Task.Delay(250);
        Application.Current.Shutdown();
    }

    private void ShowStep(LaunchStep step)
    {
        StatusTitle.Text = step.Title + "…";
        StatusDetail.Text = step.Detail;
        Progress.SetProgress(step.Progress);
    }

    private void ShowError(LaunchResult result)
    {
        StatusTitle.Text = result.Title;
        StatusDetail.Text = result.Detail;
        StatusDetail.TextWrapping = TextWrapping.Wrap;
        Progress.FillBrush = (Brush)FindResource("DangerBrush");
        Progress.Busy = false;
        Progress.SetProgress(1);
        ErrorActions.Visibility = Visibility.Visible;
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Close_Click(object sender, RoutedEventArgs e) => Application.Current.Shutdown();
    private async void Retry_Click(object sender, RoutedEventArgs e) => await RunAsync();
}
