using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Veyl.Shared;

namespace Veyl.Setup;

public sealed record SetupOptions(bool StartWithWindows = true, bool DesktopShortcut = false, bool ExplorerMenu = true, bool RemoveData = false)
{
    /// <summary>Trust veyl-signing.cer from a build.ps1 -Sign build. Only set by --trust-cert.</summary>
    public static bool TrustCertificate { get; set; }
}

public sealed record SetupStep(string Title, string Detail, double Progress, int Index, int Count);

public sealed class SetupFailed(string title, string detail) : Exception(detail)
{
    public string Title { get; } = title;
}

/// <summary>Installs, repairs and removes VEYL. Every step is written to the setup log.</summary>
public sealed class Installer
{
    public const string TaskName = @"VEYL\Launcher";
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VEYL";
    private const string MenuVerb = "VEYL.Scan";
    private static readonly string[] MenuClasses = [@"*\shell", @"Directory\shell"];
    private const string SandboxVerb = "VEYL.Sandbox";
    private static readonly string[] SandboxClasses = [@"exefile\shell", @"batfile\shell", @"cmdfile\shell"];

    public static string TargetDir { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "VEYL");
    public static string DataDir => VeylPaths.Root;
    public static string StartMenuLink => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "VEYL.lnk");
    public static string DesktopLink => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "VEYL.lnk");

    public string LogPath { get; }
    private readonly StreamWriter _log;

    public Installer()
    {
        string dir = Path.Combine(DataDir, "logs");
        try { Directory.CreateDirectory(dir); }
        catch (Exception) { dir = Path.GetTempPath(); }
        LogPath = Path.Combine(dir, $"setup-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        _log = new StreamWriter(LogPath, append: true) { AutoFlush = true };
        Log($"VEYL setup {Payload.Version} on Windows {Environment.OSVersion.Version}, user {Environment.UserName}");
    }

    public void Log(string line)
    {
        try { _log.WriteLine($"{DateTime.Now:HH:mm:ss.fff}  {line}"); }
        catch (ObjectDisposedException) { /* closed so the data folder (and the log in it) could be deleted */ }
    }

    // ---------------------------------------------------------------- what's installed now

    public static string? InstalledVersion()
    {
        using var key = Registry.LocalMachine.OpenSubKey(UninstallKey);
        if (key?.GetValue("DisplayVersion") is string v) return v;
        return Manifest.Load(TargetDir)?.Version;
    }

    public static bool TaskExists() => Run("schtasks.exe", $"/Query /TN \"{TaskName}\"", out _) == 0;

    public static bool MenuExists()
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\*\shell\{MenuVerb}");
        return key is not null;
    }

    public static bool DesktopLinkExists() => File.Exists(DesktopLink);

    // ---------------------------------------------------------------- install / repair

    public async Task InstallAsync(SetupOptions o, Action<SetupStep> report)
    {
        const int n = 8;
        void Step(int i, string title, string detail) { Log($"== {title}"); report(new(title, detail, (i - 1.0) / n, i, n)); }

        Step(1, "Checking your PC", "Windows version, disk space and permissions.");
        await Task.Run(CheckSystem);

        Step(2, "Closing VEYL", "Stopping any running copies so files can be replaced.");
        await Task.Run(CloseRunning);

        Step(3, "Copying files", TargetDir);
        await Task.Run(() => CopyFiles(file => report(new("Copying files", file, (2 + _copyFraction) / n, 3, n))));

        Step(4, "Preparing data folders", DataDir);
        await Task.Run(PrepareData);

        Step(5, o.StartWithWindows ? "Setting up start with Windows" : "Turning off start with Windows", "Sign-in task for every user.");
        await Task.Run(() => { if (o.StartWithWindows) RegisterTask(); else RemoveTask(); });

        Step(6, "Adding shortcuts", o.ExplorerMenu ? "Start menu and Explorer's right-click menu." : "Start menu.");
        await Task.Run(() => Shortcuts(o));

        Step(7, "Registering with Windows", "So VEYL shows up in Settings > Apps.");
        await Task.Run(RegisterUninstall);
        if (SetupOptions.TrustCertificate) await Task.Run(TrustSigningCertificate);

        Step(8, "Verifying the install", "Checking every file and test-running the engine.");
        await Task.Run(() => Verify(o));

        Log("Install finished OK");
        report(new("Done", "", 1, n, n));
    }

    private void CheckSystem()
    {
        var os = Environment.OSVersion.Version;
        Log($"OS {os}, 64-bit {Environment.Is64BitOperatingSystem}");
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
            throw new SetupFailed("Windows is too old", $"VEYL needs Windows 10 version 1809 or newer. This PC runs {os}.");
        if (!Environment.Is64BitOperatingSystem)
            throw new SetupFailed("64-bit Windows needed", "VEYL only runs on 64-bit (x64) Windows.");
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            throw new SetupFailed("Administrator rights needed", "Run VEYL-Setup again and accept the Windows permission prompt.");

        long need = Payload.UncompressedSize * 2 + (50L << 20);  // staging copy + headroom
        var drive = new DriveInfo(Path.GetPathRoot(TargetDir)!);
        Log($"Free space on {drive.Name}: {drive.AvailableFreeSpace >> 20} MB, need {need >> 20} MB");
        if (drive.AvailableFreeSpace < need)
            throw new SetupFailed("Not enough disk space", $"VEYL needs about {need >> 20} MB free on {drive.Name}, and there's {drive.AvailableFreeSpace >> 20} MB.");
    }

    private void CloseRunning()
    {
        foreach (string name in new[] { "Veyl.App", "VEYL" })
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                try
                {
                    Log($"Stopping {name} (pid {p.Id}, session {p.SessionId})");
                    p.Kill(entireProcessTree: true);
                    p.WaitForExit(5000);
                }
                catch (Exception ex) { Log($"  could not stop: {ex.Message}"); }
                finally { p.Dispose(); }
            }
        }

        // Explorer runs the Windows 11 menu handler in a COM surrogate (dllhost.exe), which keeps
        // Veyl.ShellMenu.dll open and would stop the install folder being replaced. Windows starts
        // a new surrogate the next time the menu opens, so closing it is harmless.
        foreach (var p in Process.GetProcessesByName("dllhost"))
        {
            try
            {
                bool ours = p.Modules.Cast<ProcessModule>().Any(m =>
                    m.ModuleName.Equals("Veyl.ShellMenu.dll", StringComparison.OrdinalIgnoreCase));
                if (!ours) continue;
                Log($"Stopping the menu handler's dllhost (pid {p.Id}, session {p.SessionId})");
                p.Kill();
                p.WaitForExit(5000);
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                // Another user's surrogate we can't inspect, or it has already gone.
            }
            finally { p.Dispose(); }
        }
    }

    private double _copyFraction;

    /// <summary>Extracts into a staging folder, then swaps it in, so a failed copy leaves the old install working.</summary>
    private void CopyFiles(Action<string> progress)
    {
        string staging = TargetDir + ".new";
        string backup = TargetDir + ".old";
        DeleteDir(staging);
        DeleteDir(backup);

        using (var zip = Payload.Open())
        {
            int done = 0, total = zip.Entries.Count;
            foreach (var entry in zip.Entries)
            {
                string dest = Path.GetFullPath(Path.Combine(staging, entry.FullName));
                if (!dest.StartsWith(staging + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw new SetupFailed("Damaged installer", $"Unexpected path in payload: {entry.FullName}");
                if (entry.FullName.EndsWith('/')) { Directory.CreateDirectory(dest); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                entry.ExtractToFile(dest, overwrite: true);
                _copyFraction = ++done / (double)total;
                if (done % 20 == 0 || done == total) progress(entry.FullName);
            }
            Log($"Extracted {total} files to {staging}");
        }

        // Keep a copy of setup in the install folder for repair and uninstall from Settings > Apps.
        string self = Environment.ProcessPath!;
        File.Copy(self, Path.Combine(staging, "VEYL-Setup.exe"), overwrite: true);

        bool hadOld = Directory.Exists(TargetDir);
        if (hadOld) Retry(() => Directory.Move(TargetDir, backup), "move the old install aside");
        try
        {
            Retry(() => Directory.Move(staging, TargetDir), "move the new files into place");
        }
        catch
        {
            if (hadOld && !Directory.Exists(TargetDir)) Directory.Move(backup, TargetDir);
            Log("Rolled back to the previous install");
            throw;
        }
        if (hadOld) DeleteDir(backup);
        Log($"Installed to {TargetDir}");
    }

    private void Retry(Action action, string what)
    {
        for (int attempt = 1; ; attempt++)
        {
            try { action(); return; }
            catch (IOException ex) when (attempt < 10)
            {
                Log($"  {what}: {ex.Message} (retry {attempt})");
                Thread.Sleep(500);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new SetupFailed("Files are in use", $"Couldn't {what}. Close anything using files in {TargetDir} and try again.");
            }
        }
    }

    private void DeleteDir(string dir)
    {
        if (!Directory.Exists(dir)) return;
        try { Directory.Delete(dir, recursive: true); }
        catch (Exception ex) { Log($"  couldn't delete {dir}: {ex.Message}"); }
    }

    private void PrepareData()
    {
        foreach (string d in new[] { "signatures", "quarantine", "users", "logs" })
            Directory.CreateDirectory(Path.Combine(DataDir, d));

        // Any user may add signatures and quarantine files. Per-user vault folders are
        // locked to their owner by the app itself.
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        foreach (string d in new[] { "signatures", "quarantine" })
        {
            var info = new DirectoryInfo(Path.Combine(DataDir, d));
            var acl = info.GetAccessControl();
            acl.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(acl);
        }

        string sig = Path.Combine(DataDir, "signatures", "hashes.txt");
        string seed = Path.Combine(TargetDir, "signatures", "hashes.txt");
        if (!File.Exists(sig) && File.Exists(seed))
        {
            File.Copy(seed, sig);
            Log("Seeded signature file");
        }
        else if (File.Exists(seed))
        {
            int added = SignatureUpdaterMerge(seed, sig);
            Log($"Merged {added} new seed signatures");
        }
    }

    private static int SignatureUpdaterMerge(string seed, string target)
    {
        var existing = SignatureUpdater.Parse(File.ReadLines(target), "");
        var incoming = SignatureUpdater.Parse(File.ReadLines(seed), "Blocklisted file");
        var add = incoming.Where(kv => !existing.ContainsKey(kv.Key)).ToList();
        if (add.Count > 0) File.AppendAllLines(target, add.Select(kv => $"{kv.Key} {kv.Value}"));
        return add.Count;
    }

    private void RegisterTask()
    {
        string exe = Path.Combine(TargetDir, "VEYL.exe");
        // Group principal = runs as whoever signs in. HighestAvailable = admins get an
        // elevated token without a UAC prompt; standard users run normally.
        string xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Description>Starts VEYL when anyone signs in.</Description></RegistrationInfo>
              <Triggers><LogonTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></LogonTrigger></Triggers>
              <Principals><Principal id="Users"><GroupId>S-1-5-32-545</GroupId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
              <Settings>
                <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>5</Priority>
              </Settings>
              <Actions Context="Users"><Exec><Command>"{exe}"</Command><Arguments>--autostart</Arguments><WorkingDirectory>{TargetDir}</WorkingDirectory></Exec></Actions>
            </Task>
            """;
        string file = Path.Combine(Path.GetTempPath(), "veyl-task.xml");
        File.WriteAllText(file, xml, Encoding.Unicode);
        int rc = Run("schtasks.exe", $"/Create /TN \"{TaskName}\" /XML \"{file}\" /F", out string output);
        File.Delete(file);
        Log($"schtasks /Create -> {rc}: {output.Trim()}");
        if (rc != 0) throw new SetupFailed("Couldn't set up start with Windows", output.Trim());
    }

    private void RemoveTask()
    {
        if (!TaskExists()) return;
        int rc = Run("schtasks.exe", $"/Delete /TN \"{TaskName}\" /F", out string output);
        Log($"schtasks /Delete -> {rc}: {output.Trim()}");
    }

    private void Shortcuts(SetupOptions o)
    {
        string exe = Path.Combine(TargetDir, "VEYL.exe");
        CreateShortcut(StartMenuLink, exe);
        if (o.DesktopShortcut) CreateShortcut(DesktopLink, exe);
        else if (File.Exists(DesktopLink)) File.Delete(DesktopLink);

        RemoveMenu();
        if (o.ExplorerMenu)
        {
            string app = Path.Combine(TargetDir, "Veyl.App.exe");
            foreach (string cls in MenuClasses)
            {
                using var verb = Registry.LocalMachine.CreateSubKey($@"SOFTWARE\Classes\{cls}\{MenuVerb}");
                verb.SetValue("MUIVerb", "Scan with VEYL");
                verb.SetValue("Icon", $"\"{app}\",0");
                using var cmd = verb.CreateSubKey("command");
                cmd.SetValue("", $"\"{app}\" --scan \"%1\"");
            }
            foreach (string cls in SandboxClasses)
            {
                using var verb = Registry.LocalMachine.CreateSubKey($@"SOFTWARE\Classes\{cls}\{SandboxVerb}");
                verb.SetValue("MUIVerb", "Run in VEYL sandbox");
                verb.SetValue("Icon", $"\"{app}\",0");
                using var cmd = verb.CreateSubKey("command");
                cmd.SetValue("", $"\"{app}\" --sandbox \"%1\"");
            }
            Log("Added 'Scan with VEYL' and 'Run in VEYL sandbox' to Explorer's menu");
            if (ModernMenu.Supported && AddModernMenu()) HideClassicMenu();
        }
        else
        {
            RemoveModernMenu();
        }
    }

    /// <summary>Windows 11's main menu: trust VEYL's certificate for packages, register the menu package.</summary>
    private bool AddModernMenu()
    {
        try
        {
            Log($"Trusted VEYL's certificate for app packages (TrustedPeople) {ModernMenu.TrustCertificate(TargetDir)}");
        }
        catch (Exception ex) when (ex is IOException or System.Security.Cryptography.CryptographicException)
        {
            Log($"Couldn't trust the package certificate, so the Windows 11 menu is skipped: {ex.Message}");
            return false;
        }
        // Not fatal: the classic entries stay visible under "Show more options".
        string? error = ModernMenu.Register(TargetDir, Payload.Manifest.Version);
        Log(error is null
            ? "Added VEYL to Windows 11's main right-click menu (Explorer shows it after it next restarts, or at next sign-in)"
            : $"Windows 11 menu package not registered: {error}");
        return error is null;
    }

    /// <summary>
    /// Windows 11 also lists packaged menu entries under "Show more options", so with the package
    /// registered the classic entries would appear twice there. ProgrammaticAccessOnly hides them
    /// from the menu but keeps the keys, which the app reads as "the menu option is on".
    /// </summary>
    private void HideClassicMenu()
    {
        foreach (var (classes, verb) in new[] { (MenuClasses, MenuVerb), (SandboxClasses, SandboxVerb) })
            foreach (string cls in classes)
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\{cls}\{verb}", writable: true);
                key?.SetValue("ProgrammaticAccessOnly", "");
            }
        Log("Hid the classic menu entries, since the package's entries show under \"Show more options\" too");
    }

    private void RemoveModernMenu()
    {
        if (!ModernMenu.Supported) return;
        string? error = ModernMenu.RemoveForAllUsers();
        Log(error is null ? "Removed the Windows 11 menu package" : $"Couldn't remove the Windows 11 menu package: {error}");
        try { Log($"Removed {ModernMenu.UntrustCertificate()} VEYL certificate(s) from TrustedPeople"); }
        catch (System.Security.Cryptography.CryptographicException ex) { Log($"Couldn't remove the certificate: {ex.Message}"); }
    }

    private void CreateShortcut(string link, string target)
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell")!;
        dynamic shell = Activator.CreateInstance(shellType)!;
        dynamic lnk = shell.CreateShortcut(link);
        lnk.TargetPath = target;
        lnk.WorkingDirectory = Path.GetDirectoryName(target);
        lnk.Description = "VEYL antivirus and password vault";
        lnk.IconLocation = target + ",0";
        lnk.Save();
        Log($"Shortcut {link}");
    }

    private void RemoveMenu()
    {
        foreach (string cls in MenuClasses)
            Registry.LocalMachine.DeleteSubKeyTree($@"SOFTWARE\Classes\{cls}\{MenuVerb}", throwOnMissingSubKey: false);
        foreach (string cls in SandboxClasses)
            Registry.LocalMachine.DeleteSubKeyTree($@"SOFTWARE\Classes\{cls}\{SandboxVerb}", throwOnMissingSubKey: false);
    }

    private void RegisterUninstall()
    {
        string setup = Path.Combine(TargetDir, "VEYL-Setup.exe");
        using var key = Registry.LocalMachine.CreateSubKey(UninstallKey);
        key.SetValue("DisplayName", "VEYL");
        key.SetValue("DisplayVersion", Payload.Version);
        key.SetValue("Publisher", "VEYL");
        key.SetValue("DisplayIcon", Path.Combine(TargetDir, "VEYL.exe") + ",0");
        key.SetValue("InstallLocation", TargetDir);
        key.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"));
        key.SetValue("UninstallString", $"\"{setup}\" --uninstall");
        key.SetValue("ModifyPath", $"\"{setup}\"");
        key.SetValue("EstimatedSize", (int)(Payload.UncompressedSize / 1024), RegistryValueKind.DWord);
        key.SetValue("NoRepair", 0, RegistryValueKind.DWord);
    }

    private void TrustSigningCertificate()
    {
        string cer = Path.Combine(TargetDir, "veyl-signing.cer");
        if (!File.Exists(cer))
        {
            Log("--trust-cert given but this build isn't signed");
            return;
        }
        using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(cer);
        foreach (var name in new[] { System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher })
        {
            using var store = new System.Security.Cryptography.X509Certificates.X509Store(name, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
            store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
            store.Add(cert);
        }
        Log($"Trusted signing certificate {cert.Thumbprint}");
    }

    private void Verify(SetupOptions o)
    {
        var manifest = Manifest.Load(TargetDir) ?? throw new SetupFailed("Install is incomplete", "manifest.json is missing.");
        foreach (var (name, expected) in manifest.Files)
        {
            string path = Path.Combine(TargetDir, name);
            if (!File.Exists(path)) throw new SetupFailed("Install is incomplete", $"{name} is missing.");
            using var fs = File.OpenRead(path);
            if (!Convert.ToHexString(SHA256.HashData(fs)).Equals(expected, StringComparison.OrdinalIgnoreCase))
                throw new SetupFailed("A file was changed during install", $"{name} doesn't match the release. Antivirus software may have altered it.");
        }
        Log($"Verified {manifest.Files.Count} files");

        string report = Path.Combine(Path.GetTempPath(), "veyl-selftest.txt");
        int rc = Run(Path.Combine(TargetDir, "Veyl.App.exe"), $"--selftest \"{report}\"", out _, timeoutMs: 30000);
        string result = File.Exists(report) ? File.ReadAllText(report) : "(no report)";
        Log($"Self-test exit {rc}:\n{result}");
        File.Delete(report);
        if (rc != 0)
        {
            string firstFail = result.Split('\n').FirstOrDefault(l => l.StartsWith("FAIL")) ?? "The engine didn't start.";
            throw new SetupFailed("VEYL can't run on this PC yet", firstFail.Trim());
        }

        if (o.StartWithWindows && !TaskExists())
            throw new SetupFailed("Start with Windows isn't set up", "The sign-in task wasn't found after creating it.");
    }

    // ---------------------------------------------------------------- uninstall

    public async Task UninstallAsync(SetupOptions o, Action<SetupStep> report)
    {
        const int n = 5;
        void Step(int i, string title, string detail) { Log($"== {title}"); report(new(title, detail, (i - 1.0) / n, i, n)); }

        Step(1, "Closing VEYL", "Stopping every running copy.");
        await Task.Run(CloseRunning);

        Step(2, "Removing start with Windows", "Deleting the sign-in task.");
        await Task.Run(RemoveTask);

        Step(3, "Removing shortcuts", "Start menu, desktop and Explorer's menu.");
        await Task.Run(() =>
        {
            foreach (string l in new[] { StartMenuLink, DesktopLink }) if (File.Exists(l)) File.Delete(l);
            RemoveMenu();
            RemoveModernMenu();  // before the files go: the package points at the install folder
            Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, throwOnMissingSubKey: false);
        });

        Step(4, "Removing files", TargetDir);
        await Task.Run(() =>
        {
            DeleteDir(TargetDir);
            if (Directory.Exists(TargetDir))
                throw new SetupFailed("Some files couldn't be removed", $"Delete {TargetDir} yourself after restarting.");
        });

        Step(5, o.RemoveData ? "Deleting your data" : "Keeping your data", DataDir);
        if (o.RemoveData)
        {
            _log.Dispose();
            await Task.Run(() => { if (Directory.Exists(DataDir)) Directory.Delete(DataDir, recursive: true); });
        }
        else Log($"Kept {DataDir}");

        report(new("Done", "", 1, n, n));
    }

    // ---------------------------------------------------------------- helpers

    public static int Run(string exe, string args, out string output, int timeoutMs = 15000)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeoutMs))
        {
            p.Kill(true);
            output = "timed out";
            return -1;
        }
        output = stdout.Result + stderr.Result;
        return p.ExitCode;
    }

    /// <summary>Starts VEYL for the signed-in user without our admin rights.</summary>
    public static void LaunchUnelevated() =>
        Process.Start("explorer.exe", $"\"{Path.Combine(TargetDir, "VEYL.exe")}\"");
}

/// <summary>The VEYL build embedded in this setup exe.</summary>
public static class Payload
{
    public static bool Present => Assembly.GetExecutingAssembly().GetManifestResourceInfo("payload.zip") is not null;

    public static ZipArchive Open() =>
        new(Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip")
            ?? throw new SetupFailed("Damaged installer", "This setup file has no VEYL build inside it. Rebuild it with build.ps1."));

    private static Manifest? _manifest;
    public static Manifest Manifest => _manifest ??= LoadManifest();
    public static string Version => Present ? Manifest.Version : "0.0.0";

    public static long UncompressedSize
    {
        get
        {
            if (!Present) return 0;
            using var zip = Open();
            return zip.Entries.Sum(e => e.Length);
        }
    }

    private static Manifest LoadManifest()
    {
        using var zip = Open();
        var entry = zip.GetEntry("manifest.json") ?? throw new SetupFailed("Damaged installer", "manifest.json missing from payload.");
        using var r = new StreamReader(entry.Open());
        return Shared.Manifest.Parse(r.ReadToEnd()) ?? throw new SetupFailed("Damaged installer", "manifest.json is unreadable.");
    }
}
