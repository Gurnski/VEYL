using System.Drawing;
using WinForms = System.Windows.Forms;

namespace Veyl.App.Services;

/// <summary>Notification-area icon with a dark context menu.</summary>
public sealed class TrayIcon : IDisposable
{
    private readonly WinForms.NotifyIcon _icon;
    private readonly WinForms.ToolStripMenuItem _lockItem;

    public TrayIcon(Action open, Action quickScan, Action exit)
    {
        var menu = new WinForms.ContextMenuStrip
        {
            Renderer = new WinForms.ToolStripProfessionalRenderer(new DarkColors()),
            ShowImageMargin = false,
            Font = new Font("Segoe UI", 9.5f),
        };
        menu.Items.Add(Item("Open VEYL", open, bold: true));
        menu.Items.Add(Item("Quick scan", quickScan));
        _lockItem = Item("Lock vault", () => AppServices.Vault.Lock());
        menu.Items.Add(_lockItem);
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add(Item("Exit", exit));
        menu.Opening += (_, _) => _lockItem.Enabled = AppServices.Vault.IsUnlocked;

        _icon = new WinForms.NotifyIcon
        {
            Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!) ?? SystemIcons.Shield,
            Text = "VEYL",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == WinForms.MouseButtons.Left) open();
        };
        _icon.BalloonTipClicked += (_, _) => open();
    }

    private static WinForms.ToolStripMenuItem Item(string text, Action onClick, bool bold = false)
    {
        var item = new WinForms.ToolStripMenuItem(text) { ForeColor = Color.FromArgb(0xF1, 0xED, 0xF5), Padding = new(4, 4, 4, 4) };
        if (bold) item.Font = new Font("Segoe UI", 9.5f, System.Drawing.FontStyle.Bold);
        item.Click += (_, _) => onClick();
        return item;
    }

    public void Notify(string title, string text, bool warning = false)
    {
        if (!AppServices.Settings.Notifications) return;
        Ui.Post(() => _icon.ShowBalloonTip(5000, title, text, warning ? WinForms.ToolTipIcon.Warning : WinForms.ToolTipIcon.Info));
    }

    public void SetStatus(string text) => _icon.Text = text.Length > 63 ? text[..63] : text;

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }

    private sealed class DarkColors : WinForms.ProfessionalColorTable
    {
        private static readonly Color Bg = Color.FromArgb(0x1E, 0x1A, 0x25);
        private static readonly Color Hover = Color.FromArgb(0x2B, 0x25, 0x35);
        private static readonly Color Line = Color.FromArgb(0x2E, 0x28, 0x38);
        public override Color ToolStripDropDownBackground => Bg;
        public override Color MenuBorder => Line;
        public override Color MenuItemBorder => Hover;
        public override Color MenuItemSelected => Hover;
        public override Color MenuItemSelectedGradientBegin => Hover;
        public override Color MenuItemSelectedGradientEnd => Hover;
        public override Color SeparatorDark => Line;
        public override Color SeparatorLight => Bg;
        public override Color ImageMarginGradientBegin => Bg;
        public override Color ImageMarginGradientMiddle => Bg;
        public override Color ImageMarginGradientEnd => Bg;
    }
}
