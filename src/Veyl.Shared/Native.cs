using System.Runtime.InteropServices;
using System.Security;

namespace Veyl.Shared;

public enum VeylStatus
{
    Ok = 0,
    BadArgument = 1,
    IoError = 2,
    AuthFailed = 3,
    BadFormat = 4,
    CryptoError = 5,
    BufferTooSmall = 6,
    NotFound = 7,
    AlreadyExists = 8,
    BadState = 9,
}

public enum Verdict
{
    Clean = 0,
    Suspicious = 1,
    Malicious = 2,
    Skipped = 3,
}

[Flags]
public enum GenFlags
{
    Lower = 0x01,
    Upper = 0x02,
    Digits = 0x04,
    Symbols = 0x08,
    NoAmbiguous = 0x10,
}

public sealed class VeylException(VeylStatus status, string message) : Exception($"{message} ({status})")
{
    public VeylStatus Status { get; } = status;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public unsafe struct NativeScanResult
{
    public int Verdict;
    public int Score;
    public fixed byte Sha256[65];
    public fixed char Threat[128];
    public fixed char Detail[256];
}

public sealed record ScanResult(string Path, Verdict Verdict, int Score, string Sha256, string Threat, string Detail)
{
    public bool IsThreat => Verdict is Verdict.Malicious or Verdict.Suspicious;

    internal static unsafe ScanResult From(string path, in NativeScanResult r)
    {
        fixed (byte* sha = r.Sha256)
        fixed (char* threat = r.Threat)
        fixed (char* detail = r.Detail)
        {
            return new ScanResult(path, (Verdict)r.Verdict, r.Score,
                Marshal.PtrToStringAnsi((IntPtr)sha) ?? "",
                new string(threat), new string(detail));
        }
    }
}

/// <summary>Raw P/Invoke surface of Veyl.Core.dll. Prefer the wrappers below.</summary>
internal static unsafe class NativeMethods
{
    private const string Dll = "Veyl.Core.dll";

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int ScanCallback(IntPtr path, NativeScanResult* result, IntPtr ctx);

    [DllImport(Dll)] public static extern IntPtr veyl_core_version();
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_sha256_file(string path, byte* outHex);
    [DllImport(Dll)] public static extern int veyl_generate_password(char* buf, int length, int flags);
    [DllImport(Dll)] public static extern void veyl_secure_zero(void* p, int bytes);
    [DllImport(Dll)] public static extern int veyl_clipboard_set_secret(char* text, int len, int clearAfterSec);

    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_vault_create(string path, char* pw, int pwLen, out IntPtr vault);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_vault_open(string path, char* pw, int pwLen, out IntPtr vault);
    [DllImport(Dll)] public static extern int veyl_vault_save(IntPtr v);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_vault_open_recovery(string path, char* key, int keyLen, out IntPtr vault);
    [DllImport(Dll)] public static extern int veyl_vault_set_recovery(IntPtr v, char* outKey);
    [DllImport(Dll)] public static extern int veyl_vault_has_recovery(IntPtr v);
    [DllImport(Dll)] public static extern int veyl_vault_change_password(IntPtr v, char* pw, int pwLen);
    [DllImport(Dll)] public static extern void veyl_vault_close(IntPtr v);
    [DllImport(Dll)] public static extern int veyl_vault_count(IntPtr v);
    [DllImport(Dll)] public static extern int veyl_vault_get_field(IntPtr v, int index, int field, char* buf, ref int len);
    [DllImport(Dll)] public static extern int veyl_vault_get_times(IntPtr v, int index, out long created, out long modified);
    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int veyl_vault_add(IntPtr v, string title, string username, char* pw, int pwLen, string url, string notes, char* outId);
    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int veyl_vault_update(IntPtr v, string id, string title, string username, char* pw, int pwLen, string url, string notes);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_vault_delete(IntPtr v, string id);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_vault_copy_password(IntPtr v, string id, int clearAfterSec);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_vault_reveal_password(IntPtr v, string id, char* buf, ref int len);

    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_scanner_init(string? signatureFile, int useAmsi);
    [DllImport(Dll)] public static extern int veyl_scanner_signature_count();
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_scanner_add_signature(string hashHex, string name);
    [DllImport(Dll)] public static extern int veyl_scanner_signature_counts(out long md5, out long sha1, out long sha256);
    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int veyl_signature_compile([MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] inputs,
        int count, string label, string outDir, char* outPath, out long hashes);
    [DllImport(Dll)] public static extern int veyl_scanner_pack_info(int index, char* label, char* path, out long hashes, out long createdUnix);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_scanner_remove_pack(string path);
    [DllImport(Dll)] public static extern void veyl_scanner_shutdown();
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_scan_file(string path, out NativeScanResult result);
    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int veyl_scan_directory(string path, ScanCallback cb, IntPtr ctx, out int files, out int threats);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_scan_file_ex(string path, int flags, out NativeScanResult result);
    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int veyl_scan_directory_ex(string path, int flags, ScanCallback cb, IntPtr ctx, out int files, out int threats);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_scan_cache_load(string path);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_scan_cache_save(string path);
    [DllImport(Dll)] public static extern void veyl_scan_cache_clear();
    [DllImport(Dll)] public static extern int veyl_scan_cache_count();

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int veyl_quarantine_file(string path, string dir, string threat, char* outId);
    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int veyl_quarantine_info(string dir, string id, char* originalPath, char* threat, out long at, out long size);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_quarantine_restore(string dir, string id, string? restoreTo);
    [DllImport(Dll, CharSet = CharSet.Unicode)] public static extern int veyl_quarantine_delete(string dir, string id);
}

public static unsafe class Core
{
    public static string Version => Marshal.PtrToStringAnsi(NativeMethods.veyl_core_version()) ?? "?";

    internal static void Check(int rc, string what)
    {
        if (rc != 0) throw new VeylException((VeylStatus)rc, what);
    }

    public static string Sha256File(string path)
    {
        byte* hex = stackalloc byte[65];
        Check(NativeMethods.veyl_sha256_file(path, hex), "Hashing failed");
        return Marshal.PtrToStringAnsi((IntPtr)hex)!;
    }

    /// <summary>Generates a password into a char array the caller should clear when done.</summary>
    public static char[] GeneratePassword(int length, GenFlags flags)
    {
        var buf = new char[length + 1];
        fixed (char* p = buf)
            Check(NativeMethods.veyl_generate_password(p, length, (int)flags), "Password generation failed");
        return buf[..length];
    }

    /// <summary>Copies a secret to the clipboard, hidden from Win+V history, and clears it later.</summary>
    public static void CopySecret(ReadOnlySpan<char> text, int clearAfterSeconds)
    {
        fixed (char* p = text)
            Check(NativeMethods.veyl_clipboard_set_secret(p, text.Length, clearAfterSeconds), "Clipboard is busy");
    }

    /// <summary>Runs <paramref name="use"/> with the SecureString's characters in unmanaged memory, then wipes it.</summary>
    internal static T WithSecure<T>(SecureString s, Func<IntPtr, int, T> use)
    {
        IntPtr p = Marshal.SecureStringToGlobalAllocUnicode(s);
        try { return use(p, s.Length); }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(p); }
    }
}

public static unsafe class Scanner
{
    public static void Init(string? signatureFile, bool useAmsi) =>
        Core.Check(NativeMethods.veyl_scanner_init(signatureFile, useAmsi ? 1 : 0), "Scanner init failed");

    public static int SignatureCount => NativeMethods.veyl_scanner_signature_count();

    public static (long Md5, long Sha1, long Sha256) SignatureCounts
    {
        get
        {
            NativeMethods.veyl_scanner_signature_counts(out long md5, out long sha1, out long sha256);
            return (md5, sha1, sha256);
        }
    }

    /// <param name="hashHex">MD5, SHA-1 or SHA-256 in hex.</param>
    public static void AddSignature(string hashHex, string name) =>
        Core.Check(NativeMethods.veyl_scanner_add_signature(hashHex, name), "Invalid signature");

    /// <summary>Signature packs the scanner has loaded, one per label.</summary>
    public static IReadOnlyList<SignaturePack> Packs
    {
        get
        {
            var list = new List<SignaturePack>();
            char* label = stackalloc char[64];
            char* path = stackalloc char[260];
            for (int i = 0; NativeMethods.veyl_scanner_pack_info(i, label, path, out long n, out long created) == 0; ++i)
                list.Add(new SignaturePack(new string(label), new string(path), n, DateTimeOffset.FromUnixTimeSeconds(created)));
            return list;
        }
    }

    /// <summary>Unloads a pack and deletes its file. Call <see cref="Init"/> afterwards in other processes.</summary>
    public static void RemovePack(string path) =>
        Core.Check(NativeMethods.veyl_scanner_remove_pack(path), "Could not remove the signature pack");

    /// <summary>
    /// Compiles hash lists (and optionally an existing pack, to merge into) into a new pack
    /// in <paramref name="outDir"/>. Slow for big lists: run it off the UI thread, then
    /// call <see cref="Init"/> to load the result.
    /// </summary>
    public static (string Path, long Hashes) CompilePack(IReadOnlyList<string> inputs, string label, string outDir)
    {
        char* path = stackalloc char[260];
        int rc = NativeMethods.veyl_signature_compile([.. inputs], inputs.Count, label, outDir, path, out long n);
        if (rc == (int)VeylStatus.BadFormat) throw new VeylException(VeylStatus.BadFormat, "No MD5, SHA-1 or SHA-256 hashes found in those files");
        Core.Check(rc, "Could not build the signature pack");
        return (new string(path), n);
    }

    public static void Shutdown() => NativeMethods.veyl_scanner_shutdown();

    /// <param name="fresh">Ignore the clean-file cache (real-time checks of new files use this).</param>
    public static ScanResult ScanFile(string path, bool fresh = false)
    {
        Core.Check(NativeMethods.veyl_scan_file_ex(path, fresh ? 1 : 0, out var r), "Scan failed");
        return ScanResult.From(path, r);
    }

    /// <summary>Scans a folder tree on a native worker pool and blocks until done.
    /// <paramref name="onFile"/> runs for every file, one call at a time, on a worker thread.</summary>
    public static (int Files, int Threats) ScanDirectory(string path, Action<ScanResult> onFile, CancellationToken token, bool fresh = false)
    {
        NativeMethods.ScanCallback cb = (p, r, _) =>
        {
            onFile(ScanResult.From(Marshal.PtrToStringUni(p) ?? "", *r));
            return token.IsCancellationRequested ? 0 : 1;
        };
        int rc = NativeMethods.veyl_scan_directory_ex(path, fresh ? 1 : 0, cb, IntPtr.Zero, out int files, out int threats);
        GC.KeepAlive(cb);
        Core.Check(rc, "Directory scan failed");
        return (files, threats);
    }

    public static int CachedCount => NativeMethods.veyl_scan_cache_count();
    public static void LoadCache(string path) => NativeMethods.veyl_scan_cache_load(path);
    public static void SaveCache(string path) => NativeMethods.veyl_scan_cache_save(path);
    public static void ClearCache() => NativeMethods.veyl_scan_cache_clear();
}

/// <summary>A program running in the VEYL sandbox. Disposing it kills the whole process tree.</summary>
public sealed unsafe class SandboxProcess : IDisposable
{
    private IntPtr _handle;

    public int Pid { get; }
    /// <summary>False for 32-bit programs: they're isolated, but their activity isn't recorded yet.</summary>
    public bool Monitored { get; }

    private SandboxProcess(IntPtr handle, int pid, bool monitored)
    {
        _handle = handle;
        Pid = pid;
        Monitored = monitored;
    }

    public static SandboxProcess Start(string exe, string args, string root, string hookDll, bool allowNetwork)
    {
        int rc = SandboxNative.veyl_sandbox_start(exe, args, root, hookDll, allowNetwork ? 1 : 0, out IntPtr h, out int pid, out int mon);
        if (rc == (int)VeylStatus.IoError)
        {
            // Windows' own reason ("not a valid Win32 application", "blocked by group policy", ...) beats "IoError".
            int err = Marshal.GetLastWin32Error();
            string reason = err != 0 ? new System.ComponentModel.Win32Exception(err).Message : "Windows refused to start it.";
            throw new VeylException(VeylStatus.IoError, $"Windows wouldn't start the program: {reason}");
        }
        Core.Check(rc, "Could not start the program in the sandbox");
        return new SandboxProcess(h, pid, mon != 0);
    }

    public (int Active, int Total, int ExitCode) Status()
    {
        if (_handle == IntPtr.Zero) return (0, 0, 0);
        SandboxNative.veyl_sandbox_status(_handle, out int active, out int total, out int code);
        return (active, total, code);
    }

    public void Kill()
    {
        if (_handle != IntPtr.Zero) SandboxNative.veyl_sandbox_kill(_handle);
    }

    public void Dispose()
    {
        if (_handle == IntPtr.Zero) return;
        SandboxNative.veyl_sandbox_close(_handle);
        _handle = IntPtr.Zero;
    }

    private static class SandboxNative
    {
        [DllImport("Veyl.Core.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int veyl_sandbox_start(string exe, string args, string root, string hookDll, int flags,
            out IntPtr sandbox, out int pid, out int monitored);
        [DllImport("Veyl.Core.dll")] public static extern int veyl_sandbox_status(IntPtr sb, out int active, out int total, out int exitCode);
        [DllImport("Veyl.Core.dll")] public static extern int veyl_sandbox_kill(IntPtr sb);
        [DllImport("Veyl.Core.dll")] public static extern void veyl_sandbox_close(IntPtr sb);
    }
}

public sealed record SignaturePack(string Label, string Path, long Hashes, DateTimeOffset Created);

public sealed record QuarantineItem(string Id, string OriginalPath, string Threat, DateTimeOffset QuarantinedAt, long Size);

public static unsafe class Quarantine
{
    public static string Add(string path, string dir, string threat)
    {
        char* id = stackalloc char[37];
        Core.Check(NativeMethods.veyl_quarantine_file(path, dir, threat, id), "Could not quarantine file");
        return new string(id);
    }

    public static QuarantineItem? Info(string dir, string id)
    {
        char* path = stackalloc char[1024];
        char* threat = stackalloc char[128];
        if (NativeMethods.veyl_quarantine_info(dir, id, path, threat, out long at, out long size) != 0) return null;
        return new QuarantineItem(id, new string(path), new string(threat), DateTimeOffset.FromUnixTimeSeconds(at), size);
    }

    public static IReadOnlyList<QuarantineItem> List(string dir)
    {
        if (!Directory.Exists(dir)) return [];
        return Directory.EnumerateFiles(dir, "*.vq")
            .Select(f => Info(dir, Path.GetFileNameWithoutExtension(f)))
            .OfType<QuarantineItem>()
            .OrderByDescending(i => i.QuarantinedAt)
            .ToList();
    }

    public static void Restore(string dir, string id, string? restoreTo = null) =>
        Core.Check(NativeMethods.veyl_quarantine_restore(dir, id, restoreTo), "Could not restore file");

    public static void Delete(string dir, string id) =>
        Core.Check(NativeMethods.veyl_quarantine_delete(dir, id), "Could not delete item");
}
