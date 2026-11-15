using Microsoft.UI.Xaml.Controls;
using Ringeris.App.Localization;
using Ringeris.App.Services;

namespace Ringeris.App.Views;

public sealed partial class ScanPage : Page
{
    public UiStrings L => LocalizationService.S;

    public ScanService Vm { get; } = ScanService.Instance;

    public ScanPage()
    {
        InitializeComponent();
        DataContext = Vm;
    }
}
