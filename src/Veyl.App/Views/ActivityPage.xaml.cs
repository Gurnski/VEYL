using System.Windows;
using System.Windows.Controls;
using Veyl.App.Services;

namespace Veyl.App.Views;

public partial class ActivityPage : UserControl, IRefreshable
{
    private string _filter = "All";

    public ActivityPage()
    {
        InitializeComponent();
        AppServices.Activity.Items.CollectionChanged += (_, _) => { if (IsVisible) Refresh(); };
    }

    public void Refresh()
    {
        if (List is null) return;  // Checked fires during InitializeComponent
        var items = AppServices.Activity.Items.Where(i => _filter switch
        {
            "Threats" => i.Kind is LogKind.Threat or LogKind.Quarantine or LogKind.Realtime,
            "Scans" => i.Kind == LogKind.Scan,
            "Vault" => i.Kind == LogKind.Vault,
            _ => true,
        }).ToList();
        List.ItemsSource = items;
        Empty.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Filter_Checked(object sender, RoutedEventArgs e)
    {
        _filter = (string)((RadioButton)sender).Content;
        Refresh();
    }
}
