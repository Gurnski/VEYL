using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;
using System.Windows.Threading;

namespace Veyl.App.Services;

public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }
}

public static class Ui
{
    public static Dispatcher Dispatcher => Application.Current.Dispatcher;

    public static void Post(Action a)
    {
        if (Dispatcher.CheckAccess()) a();
        else Dispatcher.BeginInvoke(a);
    }

    public static string Ago(DateTimeOffset? t)
    {
        if (t is null) return "Never";
        var d = DateTimeOffset.Now - t.Value;
        if (d.TotalSeconds < 60) return "Just now";
        if (d.TotalMinutes < 60) return $"{(int)d.TotalMinutes} min ago";
        if (d.TotalHours < 24) return $"{(int)d.TotalHours} hr ago";
        if (d.TotalDays < 7) return $"{(int)d.TotalDays} day{((int)d.TotalDays == 1 ? "" : "s")} ago";
        return t.Value.LocalDateTime.ToString("d MMM yyyy");
    }

    public static string Size(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        < 1024L * 1024 * 1024 => $"{bytes / 1024.0 / 1024:0.#} MB",
        _ => $"{bytes / 1024.0 / 1024 / 1024:0.##} GB",
    };

    /// <summary>Opens a URL or protocol link through Explorer, so that when VEYL runs elevated
    /// the browser still starts with the user's normal, unelevated rights.</summary>
    public static void OpenUnelevated(string target) =>
        System.Diagnostics.Process.Start("explorer.exe", $"\"{target}\"");

    public static void RevealInExplorer(string path)
    {
        string arg = File.Exists(path) ? $"/select,\"{path}\"" : $"\"{Path.GetDirectoryName(path)}\"";
        System.Diagnostics.Process.Start("explorer.exe", arg);
    }
}

public enum Strength { Empty, Weak, Fair, Strong, Excellent }

public static class PasswordStrength
{
    /// <summary>Rough entropy estimate from length and character classes. Reads the
    /// SecureString through unmanaged memory so no managed copy is made.</summary>
    public static (Strength Level, double Bits) Measure(SecureString s)
    {
        if (s.Length == 0) return (Strength.Empty, 0);
        IntPtr p = Marshal.SecureStringToGlobalAllocUnicode(s);
        try
        {
            unsafe { return Measure(new ReadOnlySpan<char>((char*)p, s.Length)); }
        }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(p); }
    }

    /// <summary>Compares two SecureStrings without copying either into a managed string.</summary>
    public static unsafe bool SecureEquals(SecureString a, SecureString b)
    {
        if (a.Length != b.Length) return false;
        IntPtr pa = Marshal.SecureStringToGlobalAllocUnicode(a);
        IntPtr pb = Marshal.SecureStringToGlobalAllocUnicode(b);
        try { return new ReadOnlySpan<char>((char*)pa, a.Length).SequenceEqual(new ReadOnlySpan<char>((char*)pb, b.Length)); }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(pa);
            Marshal.ZeroFreeGlobalAllocUnicode(pb);
        }
    }

    public static (Strength Level, double Bits) Measure(ReadOnlySpan<char> pw)
    {
        if (pw.IsEmpty) return (Strength.Empty, 0);
        bool lower = false, upper = false, digit = false, symbol = false, other = false;
        foreach (char c in pw)
        {
            if (char.IsAsciiLetterLower(c)) lower = true;
            else if (char.IsAsciiLetterUpper(c)) upper = true;
            else if (char.IsAsciiDigit(c)) digit = true;
            else if (c < 128) symbol = true;
            else other = true;
        }
        int pool = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 32 : 0) + (other ? 100 : 0);
        double bits = pw.Length * Math.Log2(Math.Max(pool, 2));
        var level = bits switch { < 40 => Strength.Weak, < 64 => Strength.Fair, < 96 => Strength.Strong, _ => Strength.Excellent };
        return (level, bits);
    }
}
