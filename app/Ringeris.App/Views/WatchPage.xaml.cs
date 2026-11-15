using Microsoft.UI.Xaml.Controls;
using Ringeris.App.Localization;
using Ringeris.App.Services;

namespace Ringeris.App.Views;

public sealed partial class WatchPage : Page
{
    public UiStrings L => LocalizationService.S;

    public WatchService Vm { get; } = WatchService.Instance;

    public WatchPage()
    {
        InitializeComponent();
        DataContext = Vm;
    }
}
