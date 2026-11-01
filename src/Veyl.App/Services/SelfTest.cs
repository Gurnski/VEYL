using System.Security;
using Veyl.Shared;

namespace Veyl.App.Services;

/// <summary>
/// "Veyl.App.exe --selftest [report.txt]": proves an install can actually run. Loads the
/// native core, initialises the scanner, scans a file, and round-trips a throwaway vault.
/// Exit code 0 = all good. Never touches the user's real vault.
/// </summary>
public static class SelfTest
{
    public static int Run(string? reportPath)
    {
        var report = new List<string>();
        int failures = 0;
        void Step(string name, Func<string> check)
        {
            try { report.Add($"ok   {name}: {check()}"); }
            catch (Exception ex)
            {
                failures++;
                report.Add($"FAIL {name}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        string temp = Path.Combine(Path.GetTempPath(), "veyl-selftest-" + Environment.ProcessId);
        Step("native core", () => "Veyl.Core " + Core.Version);
        Step("data folders", () =>
        {
            VeylPaths.EnsureCreated();
            return VeylPaths.Root;
        });
        Step("scanner", () =>
        {
            Scanner.Init(VeylPaths.SignatureFile, useAmsi: false);
            var r = Scanner.ScanFile(Environment.ProcessPath!);
            if (r.Verdict != Verdict.Clean) throw new InvalidOperationException($"own exe scanned as {r.Verdict}: {r.Detail}");
            return $"{Scanner.SignatureCount} signatures, own exe clean";
        });
        Step("vault crypto", () =>
        {
            Directory.CreateDirectory(temp);
            string file = Path.Combine(temp, "test.veyl");
            using var pw = new SecureString();
            foreach (char c in Guid.NewGuid().ToString()) pw.AppendChar(c);
            using (var v = VaultSession.Create(file, pw)) v.Add("selftest", "u", "p".AsSpan(), "", "");
            using var reopened = VaultSession.Open(file, pw) ?? throw new InvalidOperationException("reopen failed");
            if (reopened.Count != 1) throw new InvalidOperationException("entry lost");
            return "create, save, reopen";
        });
        Step("sandbox monitor", () => File.Exists(SandboxService.HookDll)
            ? "Veyl.SandboxHook.dll present"
            : throw new FileNotFoundException("Veyl.SandboxHook.dll is missing"));
        Step("generator", () => Core.GeneratePassword(16, GenFlags.Lower | GenFlags.Digits).Length == 16 ? "ok" : throw new InvalidOperationException("bad length"));

        try { Scanner.Shutdown(); } catch (Exception) { }
        try { Directory.Delete(temp, true); } catch (Exception) { }

        report.Add(failures == 0 ? "SELFTEST PASSED" : $"SELFTEST FAILED ({failures})");
        if (reportPath is not null)
        {
            try { File.WriteAllLines(reportPath, report); } catch (IOException) { }
        }
        return failures == 0 ? 0 : 1;
    }
}
