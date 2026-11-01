using System.Security.AccessControl;
using System.Security.Principal;

namespace Veyl.Shared;

/// <summary>
/// Where VEYL keeps things on disk.
///   C:\ProgramData\VEYL\signatures\hashes.txt        shared hash blocklist
///   C:\ProgramData\VEYL\quarantine\*.vq              shared quarantine
///   C:\ProgramData\VEYL\users\&lt;SID&gt;\vault.veyl    per-user encrypted vault
///   C:\ProgramData\VEYL\users\&lt;SID&gt;\settings.json per-user settings
/// Each user folder is locked down to that user, SYSTEM and Administrators.
/// </summary>
public static class VeylPaths
{
    public static string Root { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VEYL");

    public static string InstallDir { get; } = AppContext.BaseDirectory;
    public static string SignatureDir => Path.Combine(Root, "signatures");
    public static string SignatureFile => Path.Combine(SignatureDir, "hashes.txt");
    public static string QuarantineDir => Path.Combine(Root, "quarantine");
    public static string UsersDir => Path.Combine(Root, "users");

    public static string UserSid { get; } = WindowsIdentity.GetCurrent().User!.Value;
    public static string UserName { get; } = Environment.UserName;
    public static string UserDir => Path.Combine(UsersDir, UserSid);
    public static string VaultFile => Path.Combine(UserDir, "vault.veyl");
    public static string SettingsFile => Path.Combine(UserDir, "settings.json");
    public static string ActivityFile => Path.Combine(UserDir, "activity.jsonl");
    public static string ScanCacheFile => Path.Combine(UserDir, "scan.cache");

    /// <summary>Creates the folder structure and seeds the signature file. Safe to call repeatedly.</summary>
    public static void EnsureCreated()
    {
        Directory.CreateDirectory(SignatureDir);
        Directory.CreateDirectory(QuarantineDir);
        Directory.CreateDirectory(UsersDir);

        if (!Directory.Exists(UserDir))
        {
            Directory.CreateDirectory(UserDir);
            LockDownUserDir(UserDir);
        }

        if (!File.Exists(SignatureFile))
        {
            string seed = Path.Combine(InstallDir, "signatures", "hashes.txt");
            if (File.Exists(seed)) File.Copy(seed, SignatureFile);
            else File.WriteAllText(SignatureFile, "# VEYL hash signatures\n");
        }
    }

    private static void LockDownUserDir(string dir)
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var who in new IdentityReference[]
                 {
                     new SecurityIdentifier(UserSid),
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                 })
        {
            sec.AddAccessRule(new FileSystemAccessRule(who, FileSystemRights.FullControl, inherit,
                PropagationFlags.None, AccessControlType.Allow));
        }
        try { new DirectoryInfo(dir).SetAccessControl(sec); }
        catch (UnauthorizedAccessException) { /* left with inherited ACL; vault is still encrypted */ }
    }
}
