using System.Security;

namespace Veyl.Shared;

/// <summary>Non-secret view of a vault entry. The password never leaves native memory
/// except through <see cref="VaultSession.CopyPassword"/> and <see cref="VaultSession.RevealPassword"/>.</summary>
public sealed record VaultEntry(string Id, string Title, string Username, string Url, string Notes,
    DateTimeOffset Created, DateTimeOffset Modified);

public sealed unsafe class VaultSession : IDisposable
{
    private IntPtr _handle;

    private VaultSession(IntPtr handle) => _handle = handle;

    public static bool Exists(string path) => File.Exists(path);

    public static VaultSession Create(string path, SecureString masterPassword)
    {
        IntPtr h = IntPtr.Zero;
        int rc = Core.WithSecure(masterPassword, (p, n) => NativeMethods.veyl_vault_create(path, (char*)p, n, out h));
        Core.Check(rc, "Could not create vault");
        return new VaultSession(h);
    }

    /// <summary>Opens a vault. Returns null if the password is wrong.</summary>
    public static VaultSession? Open(string path, SecureString masterPassword)
    {
        IntPtr h = IntPtr.Zero;
        int rc = Core.WithSecure(masterPassword, (p, n) => NativeMethods.veyl_vault_open(path, (char*)p, n, out h));
        if (rc == (int)VeylStatus.AuthFailed) return null;
        Core.Check(rc, "Could not open vault");
        return new VaultSession(h);
    }

    /// <summary>Opens a vault with its recovery key. Returns null if the key is wrong;
    /// throws <see cref="VeylException"/> with <see cref="VeylStatus.BadState"/> if the vault has no recovery key.</summary>
    public static VaultSession? OpenWithRecoveryKey(string path, SecureString key)
    {
        IntPtr h = IntPtr.Zero;
        int rc = Core.WithSecure(key, (p, n) => NativeMethods.veyl_vault_open_recovery(path, (char*)p, n, out h));
        if (rc == (int)VeylStatus.AuthFailed) return null;
        Core.Check(rc, "Could not open vault");
        return new VaultSession(h);
    }

    public bool HasRecoveryKey => NativeMethods.veyl_vault_has_recovery(Handle) != 0;

    /// <summary>Creates a new recovery key (replacing any old one) and saves the vault.
    /// Returns XXXX-XXXX-... as a char array; clear it when done.</summary>
    public char[] CreateRecoveryKey()
    {
        var buf = new char[40];
        fixed (char* p = buf)
            Core.Check(NativeMethods.veyl_vault_set_recovery(Handle, p), "Could not create recovery key");
        int len = Array.IndexOf(buf, '\0');
        var key = buf[..len];
        Array.Clear(buf);
        return key;
    }

    private IntPtr Handle => _handle != IntPtr.Zero ? _handle : throw new ObjectDisposedException(nameof(VaultSession));

    public int Count => NativeMethods.veyl_vault_count(Handle);

    public IReadOnlyList<VaultEntry> Entries()
    {
        var list = new List<VaultEntry>();
        int n = Count;
        for (int i = 0; i < n; i++)
        {
            NativeMethods.veyl_vault_get_times(Handle, i, out long c, out long m);
            list.Add(new VaultEntry(Field(i, 0), Field(i, 1), Field(i, 2), Field(i, 3), Field(i, 4),
                DateTimeOffset.FromUnixTimeSeconds(c), DateTimeOffset.FromUnixTimeSeconds(m)));
        }
        return list;
    }

    private string Field(int index, int field)
    {
        int len = 256;
        while (true)
        {
            var buf = new char[len];
            fixed (char* p = buf)
            {
                int rc = NativeMethods.veyl_vault_get_field(Handle, index, field, p, ref len);
                if (rc == (int)VeylStatus.BufferTooSmall) continue;
                Core.Check(rc, "Could not read entry");
                return new string(p);
            }
        }
    }

    public string Add(string title, string username, ReadOnlySpan<char> password, string url, string notes)
    {
        char* id = stackalloc char[37];
        fixed (char* pw = password)
            Core.Check(NativeMethods.veyl_vault_add(Handle, title, username, pw, password.Length, url, notes, id), "Could not add entry");
        Save();
        return new string(id);
    }

    public string Add(string title, string username, SecureString password, string url, string notes)
    {
        string id = "";
        Core.WithSecure(password, (p, n) =>
        {
            id = Add(title, username, new ReadOnlySpan<char>((char*)p, n), url, notes);
            return 0;
        });
        return id;
    }

    /// <summary>Updates an entry. A null password keeps the current one.</summary>
    public void Update(string id, string title, string username, SecureString? password, string url, string notes)
    {
        int rc = password is null
            ? NativeMethods.veyl_vault_update(Handle, id, title, username, null, 0, url, notes)
            : Core.WithSecure(password, (p, n) => NativeMethods.veyl_vault_update(Handle, id, title, username, (char*)p, n, url, notes));
        Core.Check(rc, "Could not update entry");
        Save();
    }

    public void Delete(string id)
    {
        Core.Check(NativeMethods.veyl_vault_delete(Handle, id), "Could not delete entry");
        Save();
    }

    public void CopyPassword(string id, int clearAfterSeconds) =>
        Core.Check(NativeMethods.veyl_vault_copy_password(Handle, id, clearAfterSeconds), "Could not copy password");

    /// <summary>Returns the password as a string for display. Only call when the user asks to see it.</summary>
    public string RevealPassword(string id)
    {
        int len = 128;
        while (true)
        {
            var buf = new char[len];
            fixed (char* p = buf)
            {
                try
                {
                    int rc = NativeMethods.veyl_vault_reveal_password(Handle, id, p, ref len);
                    if (rc == (int)VeylStatus.BufferTooSmall) continue;
                    Core.Check(rc, "Could not read password");
                    return new string(p);
                }
                finally
                {
                    NativeMethods.veyl_secure_zero(p, buf.Length * sizeof(char));
                }
            }
        }
    }

    public void ChangeMasterPassword(SecureString newPassword) =>
        Core.Check(Core.WithSecure(newPassword, (p, n) => NativeMethods.veyl_vault_change_password(Handle, (char*)p, n)),
            "Could not change master password");

    public void Save() => Core.Check(NativeMethods.veyl_vault_save(Handle), "Could not save vault");

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            NativeMethods.veyl_vault_close(_handle);
            _handle = IntPtr.Zero;
        }
    }
}
