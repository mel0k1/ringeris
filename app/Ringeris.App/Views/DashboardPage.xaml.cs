using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Ringeris.App.Localization;
using Ringeris.App.Services;

namespace Ringeris.App.Views;

public sealed partial class DashboardPage : Page
{
    public UiStrings L => LocalizationService.S;

    public DashboardService Vm { get; } = new();

    public UpdateService U => UpdateService.Instance;

    public DashboardPage()
    {
        InitializeComponent();
        _ = Vm.RefreshAsync();
    }

    private void OnGoToWatch(object sender, RoutedEventArgs e)
    {
        Frame.Navigate(typeof(WatchPage));
    }
}
