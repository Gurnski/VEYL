using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace Veyl.Shared;

/// <summary>Native Windows 11 rounded corners and dark frame for borderless WPF windows,
/// without AllowsTransparency (which disables hardware acceleration).</summary>
public static class WindowHelper
{
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWA_BORDER_COLOR = 34;
    private const int DWMWCP_ROUND = 2;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    public static void ApplyDarkRounded(Window window, uint borderColorBgr = 0x00302532)
    {
        void Apply()
        {
            IntPtr hwnd = new WindowInteropHelper(window).Handle;
            int on = 1, round = DWMWCP_ROUND, border = (int)borderColorBgr;
            DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref on, sizeof(int));
            DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref round, sizeof(int));
            DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, ref border, sizeof(int));
        }

        if (new WindowInteropHelper(window).Handle != IntPtr.Zero) Apply();
        else window.SourceInitialized += (_, _) => Apply();
    }
}

/// <summary>Names shared between the launcher and the app for single-instance handling.</summary>
public static class InstanceNames
{
    // Local\ = per logon session, so each signed-in user gets their own instance.
    public const string AppMutex = @"Local\VEYL.App.Instance";
    public const string ShowEvent = @"Local\VEYL.App.Show";
    public const string ReadyEvent = @"Local\VEYL.App.Ready";

    // An elevated VEYL (started by the sign-in task) would otherwise create these with an
    // admin-only ACL, and an unelevated launch from Explorer couldn't open them.
    private static System.Security.Principal.SecurityIdentifier User => new(VeylPaths.UserSid);

    public static Mutex CreateAppMutex(out bool createdNew)
    {
        var security = new System.Security.AccessControl.MutexSecurity();
        security.AddAccessRule(new System.Security.AccessControl.MutexAccessRule(User,
            System.Security.AccessControl.MutexRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
        return MutexAcl.Create(true, AppMutex, out createdNew, security);
    }

    public static EventWaitHandle CreateEvent(string name, EventResetMode mode)
    {
        var security = new System.Security.AccessControl.EventWaitHandleSecurity();
        security.AddAccessRule(new System.Security.AccessControl.EventWaitHandleAccessRule(User,
            System.Security.AccessControl.EventWaitHandleRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
        return EventWaitHandleAcl.Create(false, mode, name, out _, security);
    }

    public static bool AppIsRunning()
    {
        try
        {
            if (Mutex.TryOpenExisting(AppMutex, out var m)) { m.Dispose(); return true; }
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return true;  // it exists, we just can't open it (an older build without the user ACL)
        }
    }

    public static void SignalShow()
    {
        if (EventWaitHandle.TryOpenExisting(ShowEvent, out var e)) { e.Set(); e.Dispose(); }
    }
}

/// <summary>
/// Hands a command line to the running app (e.g. "--scan C:\file.exe" from Explorer's menu).
/// One pipe per user; only that user may connect, whether or not either side is elevated.
/// </summary>
public static class AppCommands
{
    public static string PipeName => "VEYL.App." + VeylPaths.UserSid;

    public static bool TrySend(IReadOnlyList<string> args)
    {
        try
        {
            using var pipe = new System.IO.Pipes.NamedPipeClientStream(".", PipeName, System.IO.Pipes.PipeDirection.Out);
            pipe.Connect(1500);
            using var w = new StreamWriter(pipe);
            foreach (string a in args) w.WriteLine(a);
            return true;
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Calls <paramref name="onCommand"/> (on a background thread) for every command line received.</summary>
    public static void Listen(Action<string[]> onCommand, CancellationToken token)
    {
        var security = new System.IO.Pipes.PipeSecurity();
        security.AddAccessRule(new System.IO.Pipes.PipeAccessRule(
            new System.Security.Principal.SecurityIdentifier(VeylPaths.UserSid),
            System.IO.Pipes.PipeAccessRights.ReadWrite, System.Security.AccessControl.AccessControlType.Allow));

        var thread = new Thread(() =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    using var server = System.IO.Pipes.NamedPipeServerStreamAcl.Create(PipeName, System.IO.Pipes.PipeDirection.In, 1,
                        System.IO.Pipes.PipeTransmissionMode.Byte, System.IO.Pipes.PipeOptions.None, 0, 0, security);
                    server.WaitForConnection();
                    using var r = new StreamReader(server);
                    var lines = new List<string>();
                    while (r.ReadLine() is { } line && lines.Count < 64) lines.Add(line);
                    if (lines.Count > 0) onCommand(lines.ToArray());
                }
                catch (IOException) { Thread.Sleep(200); }
            }
        }) { IsBackground = true, Name = "VEYL command pipe" };
        thread.Start();
    }
}
