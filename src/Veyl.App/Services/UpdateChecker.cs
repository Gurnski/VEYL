using Veyl.Shared;

namespace Veyl.App.Services;

/// <summary>
/// Looks for a newer release while VEYL runs. The launcher checks once at sign-in, but VEYL
/// then sits in the tray for days, so the app checks again every few hours. A newer version
/// shows the Overview banner and one tray notification; nothing downloads until the user asks.
/// </summary>
public sealed class UpdateChecker
{
    public static readonly TimeSpan Interval = TimeSpan.FromHours(6);
    // The launcher has only just checked when the app starts, so wait a little before the first check.
    private static readonly TimeSpan FirstDelay = TimeSpan.FromMinutes(2);

    private readonly SemaphoreSlim _busy = new(1, 1);
    private string? _notified;

    public DateTimeOffset? LastChecked { get; private set; }
    public string? LastError { get; private set; }
    public bool IsChecking { get; private set; }

    /// <summary>False for development builds and builds made with -UpdateUrl "".</summary>
    public static bool Enabled => AppServices.Manifest is { UpdateUrl.Length: > 0 };

    public void Start(CancellationToken token)
    {
        if (!Enabled) return;
        _notified = AppServices.UpdateVersion;  // the launcher's find: already shown in the banner
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(FirstDelay, token);
                using var timer = new PeriodicTimer(Interval);
                do await CheckAsync(token);
                while (await timer.WaitForNextTickAsync(token));
            }
            catch (OperationCanceledException) { }
        }, token);
    }

    /// <summary>Returns the newer version, or null when up to date or the check failed (see LastError).</summary>
    public async Task<string?> CheckAsync(CancellationToken token = default)
    {
        if (!Enabled) return null;
        await _busy.WaitAsync(token);
        IsChecking = true;
        AppServices.Raise();
        try
        {
            var remote = await Updater.FetchRemoteAsync(AppServices.Manifest!.UpdateUrl, token);
            LastChecked = DateTimeOffset.Now;
            LastError = null;
            if (!Manifest.IsNewer(remote.Version, AppServices.Version)) return null;

            AppServices.UpdateVersion = remote.Version;
            if (_notified != remote.Version)
            {
                _notified = remote.Version;
                AppServices.Activity.Add(LogKind.System, $"VEYL {remote.Version} is available", "Download it from the Overview page");
                AppServices.Tray?.Notify($"VEYL {remote.Version} is available", "Open VEYL to download and install it.");
            }
            return remote.Version;
        }
        catch (UpdateFailed ex)
        {
            // Offline, GitHub down, or no release yet. Try again next time.
            LastChecked = DateTimeOffset.Now;
            LastError = ex.Message;
            return null;
        }
        finally
        {
            IsChecking = false;
            _busy.Release();
            AppServices.Raise();
        }
    }
}
