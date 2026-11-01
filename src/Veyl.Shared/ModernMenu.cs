using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace Veyl.Shared;

/// <summary>
/// The Windows 11 main right-click menu entries ("Run in VEYL sandbox", "Scan with VEYL").
/// Windows only shows menu handlers from a packaged app there, so Veyl.ShellMenu.dll is
/// registered through Veyl.Menu.msix, a sparse package whose files stay in the install folder.
///
/// Packages are registered per user. Setup registers it for whoever installs VEYL, and the
/// app registers it once for every other user the first time they run this version.
/// The package is signed with VEYL's own certificate, which setup trusts in the machine's
/// TrustedPeople store only (the store Windows checks for app packages).
/// </summary>
public static class ModernMenu
{
    public const string PackageName = "VEYL.ShellMenu";
    public const string PackageFile = "Veyl.Menu.msix";
    public const string CertificateFile = "veyl-signing.cer";

    /// <summary>Windows 11 (build 22000) added the menu these entries go in.</summary>
    public static bool Supported => Environment.OSVersion.Version.Build >= 22000;

    public static string PackagePath(string installDir) => Path.Combine(installDir, PackageFile);

    /// <summary>Registers the package for the current user. Returns null on success, else the reason.</summary>
    public static string? Register(string installDir, string version)
    {
        string msix = PackagePath(installDir);
        if (!File.Exists(msix)) return $"{PackageFile} is missing";
        // Skip if this version is already registered for this user (e.g. setup just did it).
        // -ExternalLocation is where the package's files really are: the install folder.
        int rc = PowerShell(
            $"if (Get-AppxPackage -Name {PackageName} | Where-Object Version -eq {Quote(version + ".0")}) {{ exit 0 }}; " +
            $"Add-AppxPackage -Path {Quote(msix)} -ExternalLocation {Quote(installDir.TrimEnd('\\'))} -ForceApplicationShutdown",
            out string output);
        return rc == 0 ? null : Clean(output);
    }

    /// <summary>Removes the package for every user. Needs admin rights.</summary>
    public static string? RemoveForAllUsers()
    {
        int rc = PowerShell($"Get-AppxPackage -AllUsers -Name {PackageName} | Remove-AppxPackage -AllUsers", out string output);
        return rc == 0 ? null : Clean(output);
    }

    /// <summary>Trusts veyl-signing.cer for app packages on this PC. Needs admin rights.</summary>
    public static string TrustCertificate(string installDir)
    {
        using var cert = new X509Certificate2(Path.Combine(installDir, CertificateFile));
        using var store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
        return cert.Thumbprint;
    }

    /// <summary>Removes VEYL's certificate from TrustedPeople. Needs admin rights.</summary>
    public static int UntrustCertificate()
    {
        using var store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        var ours = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, "CN=VEYL Local Code Signing", false);
        foreach (var c in ours) store.Remove(c);
        return ours.Count;
    }

    private static string Quote(string s) => "'" + s.Replace("'", "''") + "'";

    private static string Clean(string output) => string.Join(" ", output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Trim()).Take(6));

    private static int PowerShell(string command, out string output)
    {
        string exe = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                     "$ErrorActionPreference = 'Stop'; " + command })
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(60000))
        {
            try { p.Kill(true); } catch (InvalidOperationException) { }
            output = "PowerShell timed out";
            return -1;
        }
        output = stdout.Result + stderr.Result;
        return p.ExitCode;
    }
}
