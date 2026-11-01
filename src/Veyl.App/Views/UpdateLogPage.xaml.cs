using System.Windows.Controls;
using Veyl.App.Services;

namespace Veyl.App.Views;

public partial class UpdateLogPage : UserControl, IRefreshable
{
    public UpdateLogPage() => InitializeComponent();

    public void Refresh() => Releases.ItemsSource = ReleaseNotes.All;
}
