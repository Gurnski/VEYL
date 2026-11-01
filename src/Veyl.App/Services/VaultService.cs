using System.Collections.ObjectModel;
using System.Security;
using System.Windows.Threading;
using Microsoft.Win32;
using Veyl.Shared;

namespace Veyl.App.Services;

/// <summary>Owns the unlocked vault session, auto-locks it after inactivity and when Windows locks.</summary>
public sealed class VaultService : Observable, IDisposable
{
    private VaultSession? _session;
    private readonly DispatcherTimer _idle = new();

    public ObservableCollection<VaultEntry> Entries { get; } = [];

    public VaultService()
    {
        _idle.Tick += (_, _) => Lock("auto-locked after inactivity");
        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
    }

    public bool Exists => VaultSession.Exists(VeylPaths.VaultFile);
    public bool IsUnlocked => _session is not null;
    public int Count => Entries.Count;

    public void Create(SecureString master)
    {
        _session = VaultSession.Create(VeylPaths.VaultFile, master);
        AppServices.Activity.Add(LogKind.Vault, "Vault created", VeylPaths.VaultFile);
        Opened();
    }

    /// <summary>Returns false if the master password is wrong.</summary>
    public async Task<bool> UnlockAsync(SecureString master)
    {
        // Key derivation is deliberately slow (600k PBKDF2 rounds); keep the UI responsive.
        var session = await Task.Run(() => VaultSession.Open(VeylPaths.VaultFile, master));
        if (session is null)
        {
            AppServices.Activity.Add(LogKind.Vault, "Failed unlock attempt");
            return false;
        }
        _session = session;
        AppServices.Activity.Add(LogKind.Vault, "Vault unlocked");
        Opened();
        return true;
    }

    /// <summary>"Forgot password": opens with the recovery key and sets a new master password.
    /// Returns false if the key is wrong.</summary>
    public async Task<bool> ResetWithRecoveryKeyAsync(SecureString recoveryKey, SecureString newMaster)
    {
        var session = await Task.Run(() => VaultSession.OpenWithRecoveryKey(VeylPaths.VaultFile, recoveryKey));
        if (session is null)
        {
            AppServices.Activity.Add(LogKind.Vault, "Failed recovery attempt");
            return false;
        }
        await Task.Run(() => session.ChangeMasterPassword(newMaster));
        _session = session;
        AppServices.Activity.Add(LogKind.Vault, "Master password reset with recovery key");
        Opened();
        return true;
    }

    public bool HasRecoveryKey => _session?.HasRecoveryKey ?? false;

    /// <summary>Makes a new recovery key (the old one stops working). Clear the result when shown.</summary>
    public char[] CreateRecoveryKey()
    {
        var key = Session.CreateRecoveryKey();
        AppServices.Activity.Add(LogKind.Vault, "New recovery key created");
        Raise(nameof(HasRecoveryKey));
        return key;
    }

    private void Opened()
    {
        Reload();
        Touch();
        Changed();
    }

    public void Lock(string reason = "locked")
    {
        if (_session is null) return;
        _session.Dispose();
        _session = null;
        _idle.Stop();
        Entries.Clear();
        AppServices.Activity.Add(LogKind.Vault, "Vault locked", reason);
        Changed();
    }

    /// <summary>Resets the auto-lock countdown. Call on any vault interaction.</summary>
    public void Touch()
    {
        int minutes = AppServices.Settings.VaultAutoLockMinutes;
        _idle.Stop();
        if (minutes > 0 && IsUnlocked)
        {
            _idle.Interval = TimeSpan.FromMinutes(minutes);
            _idle.Start();
        }
    }

    public VaultSession Session
    {
        get
        {
            Touch();
            return _session ?? throw new InvalidOperationException("Vault is locked");
        }
    }

    public void Reload()
    {
        Entries.Clear();
        if (_session is null) return;
        foreach (var e in _session.Entries().OrderBy(e => e.Title, StringComparer.CurrentCultureIgnoreCase))
            Entries.Add(e);
        Raise(nameof(Count));
    }

    private void Changed()
    {
        Raise(nameof(IsUnlocked));
        Raise(nameof(Exists));
        Raise(nameof(Count));
        AppServices.Raise();
    }

    private void OnSessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff or SessionSwitchReason.ConsoleDisconnect)
            Ui.Post(() => Lock("Windows session locked"));
    }

    private void OnPowerModeChanged(object? sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend) Ui.Post(() => Lock("computer went to sleep"));
    }

    public void Dispose()
    {
        SystemEvents.SessionSwitch -= OnSessionSwitch;
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        _session?.Dispose();
        _session = null;
    }
}
