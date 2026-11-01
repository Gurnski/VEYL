using System.Windows.Controls;
using Veyl.App.Services;
using Veyl.Shared;

namespace Veyl.App.Views;

public partial class AboutPage : UserControl, IRefreshable
{
    public AboutPage() => InitializeComponent();

    public void Refresh()
    {
        var m = AppServices.Manifest;
        AppTile.Value = AppServices.Version;
        AppTile.Note = m?.Channel ?? "development";
        CoreTile.Value = Core.Version;
        InstallTile.Value = VeylPaths.InstallDir.TrimEnd('\\');
        DataTile.Value = VeylPaths.Root;
        UserTile.Value = VeylPaths.UserName;
        UserTile.Note = VeylPaths.UserSid;
        BuildTile.Value = m is null ? "Not from a release build" : m.BuildDate;
        BuildTile.Note = m is null ? "No manifest.json, so integrity checks are off" : $"{m.Files.Count} files verified at launch";
    }
}
